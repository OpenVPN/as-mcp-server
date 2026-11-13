"""Ask the administrator before a change is written, on both MCP protocol eras.

Handshake era (up to 2025-11-25): the server sends an elicitation request and waits.
2026-07-28 era: there is no such back channel. The tool returns an
`InputRequiredResult`; the client shows the prompt and calls the tool again with the
answer. Between the two calls the arguments or the server state may differ, so the
answer is bound to both and is good for one use.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Any

import mcp_types
from fastmcp import Context
from mcp.shared.exceptions import MCPError
from mcp_types.version import MODERN_PROTOCOL_VERSIONS

from as_mcp_server.settings import Approval

REQUEST_KEY = "approve"
FIELD = "approve"
SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {FIELD: {"type": "boolean", "title": "Apply this change?"}},
    "required": [FIELD],
}
# Prompts that were shown and not answered yet. In memory on purpose: a prompt from
# before a restart is not an approval. Bounded, so unanswered prompts cannot grow it.
MAX_PENDING = 1000
_issued: dict[str, None] = {}


class Decision(Enum):
    APPROVED = "approved"
    CANCELLED = "cancelled"
    NO_ELICITATION = "no_elicitation"
    # The server state is not the one the administrator saw.
    STALE = "stale"


@dataclass(frozen=True)
class Binding:
    """What an approval is for: these arguments, and this state before the change."""

    args_hash: str
    state_hash: str


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def binding(tool: str, args: Any, before: Any) -> Binding:
    return Binding(_digest([tool, args]), _digest(before))


async def ask(
    ctx: Context, mode: Approval, text: str, bind: Binding
) -> Decision | mcp_types.InputRequiredResult:
    """The administrator's decision, or the result that makes the client ask."""
    if mode == "auto":
        return Decision.APPROVED
    if _protocol_version(ctx) in MODERN_PROTOCOL_VERSIONS:
        return _ask_by_return(ctx, text, bind)
    if not _can_show_a_form(ctx):
        return Decision.NO_ELICITATION
    try:
        result = await ctx.elicit(text, response_type=bool)
    except MCPError:
        # The app announced elicitation and then refused the request.
        return Decision.NO_ELICITATION
    if result.action == "accept" and result.data is True:
        return Decision.APPROVED
    return Decision.CANCELLED


def _ask_by_return(
    ctx: Context, text: str, bind: Binding
) -> Decision | mcp_types.InputRequiredResult:
    responses = ctx.input_responses
    if responses is None:
        if not _can_show_a_form(ctx):
            return Decision.NO_ELICITATION
        nonce = uuid.uuid4().hex
        _issued[nonce] = None
        while len(_issued) > MAX_PENDING:
            del _issued[next(iter(_issued))]
        return mcp_types.InputRequiredResult(
            input_requests={
                REQUEST_KEY: mcp_types.ElicitRequest(
                    params=mcp_types.ElicitRequestFormParams(
                        message=text, requested_schema=SCHEMA
                    )
                )
            },
            request_state=json.dumps(
                {"args": bind.args_hash, "state": bind.state_hash, "nonce": nonce}
            ),
        )
    state = _state(ctx.request_state)
    if state is None or state["args"] != bind.args_hash:
        return Decision.CANCELLED
    if state["nonce"] not in _issued:
        return Decision.CANCELLED
    # One use, whatever the answer is.
    del _issued[state["nonce"]]
    if state["state"] != bind.state_hash:
        return Decision.STALE
    answer = responses.get(REQUEST_KEY)
    if (
        isinstance(answer, mcp_types.ElicitResult)
        and answer.action == "accept"
        and isinstance(answer.content, dict)
        and answer.content.get(FIELD) is True
    ):
        return Decision.APPROVED
    return Decision.CANCELLED


def _state(raw: str | None) -> dict[str, str] | None:
    if raw is None:
        return None
    try:
        state = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(state, dict):
        return None
    if not all(isinstance(state.get(key), str) for key in ("args", "state", "nonce")):
        return None
    return state


def _protocol_version(ctx: Context) -> str | None:
    request = ctx.request_context
    return request.protocol_version if request is not None else None


def _can_show_a_form(ctx: Context) -> bool:
    """True when the app said it can show a form prompt.

    `elicitation: {}` is the older way to say "form"; an app that names only `url`
    cannot show a yes/no form.
    """
    capabilities = ctx.session.client_capabilities
    elicitation = capabilities.elicitation if capabilities is not None else None
    if elicitation is None:
        return False
    return elicitation.form is not None or elicitation.url is None
