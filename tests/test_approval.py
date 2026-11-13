"""Nothing counts as an approval except this administrator saying yes to this change."""

from __future__ import annotations

import json
from typing import Any

import mcp_types
import pytest
from fastmcp import Client, Context, FastMCP
from mcp.shared.exceptions import MCPError

from as_mcp_server import approval
from as_mcp_server.approval import Binding, Decision, ask, binding, canonical
from tests.conftest import MODES, call_tool, elicitation_handler

TEXT = "Server: https://as.example:943\nAction: Block user (1 item)\n\n- bob"
YES = {"approve": mcp_types.ElicitResult(action="accept", content={"approve": True})}


def server(approval_mode: str = "prompt") -> tuple[FastMCP, dict[str, Any]]:
    """A server with one tool that asks for approval of `target`; `world` is the
    server state the approval is bound to."""
    mcp = FastMCP("approval-test")
    world: dict[str, Any] = {"state": {"deny": False}, "asked": 0}

    @mcp.tool
    async def change(ctx: Context, target: str = "bob") -> Any:
        world["asked"] += 1
        bind = binding("change", {"target": target}, world["state"])
        decision = await ask(ctx, approval_mode, TEXT, bind)  # type: ignore[arg-type]
        if isinstance(decision, Decision):
            return {"decision": decision.name}
        return decision

    return mcp, world


@pytest.fixture(autouse=True)
def no_pending_prompts():
    approval._issued.clear()
    yield
    approval._issued.clear()


@pytest.mark.parametrize("mode", MODES)
async def test_accept_with_yes_is_approved(mode: str) -> None:
    mcp, world = server()
    seen: list[str] = []
    result = await call_tool(mcp, "change", mode=mode, answer="accept", seen=seen)
    assert result == {"decision": "APPROVED"}
    assert seen == [TEXT]
    assert world["asked"] == (2 if mode != "legacy" else 1)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("answer", ["no", "decline", "cancel"])
async def test_accept_with_no_decline_and_cancel_are_cancelled(
    mode: str, answer: str
) -> None:
    mcp, _ = server()
    result = await call_tool(mcp, "change", mode=mode, answer=answer)  # type: ignore[arg-type]
    assert result == {"decision": "CANCELLED"}


@pytest.mark.parametrize("mode", MODES)
async def test_a_client_without_elicitation_gets_no_elicitation(mode: str) -> None:
    mcp, world = server()
    result = await call_tool(mcp, "change", mode=mode, answer="none")
    assert result == {"decision": "NO_ELICITATION"}
    assert world["asked"] == 1 and approval._issued == {}


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("answer", ["cancel", "none"])
async def test_auto_mode_never_asks(mode: str, answer: str) -> None:
    mcp, world = server("auto")
    seen: list[str] = []
    result = await call_tool(mcp, "change", mode=mode, answer=answer, seen=seen)  # type: ignore[arg-type]
    assert result == {"decision": "APPROVED"}
    assert seen == [] and world["asked"] == 1


@pytest.mark.parametrize("mode", MODES)
async def test_an_app_that_only_opens_links_cannot_show_the_prompt(
    mode: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`elicitation: {"url": {}}` is not a form."""
    monkeypatch.setattr(approval, "_can_show_a_form", lambda ctx: False)
    mcp, _ = server()
    seen: list[str] = []
    result = await call_tool(mcp, "change", mode=mode, answer="accept", seen=seen)
    assert result == {"decision": "NO_ELICITATION"} and seen == []


def _form(elicitation: mcp_types.ElicitationCapability | None) -> bool:
    class Session:
        client_capabilities = mcp_types.ClientCapabilities(elicitation=elicitation)

    class Ctx:
        session = Session()

    return approval._can_show_a_form(Ctx())  # type: ignore[arg-type]


def test_a_client_that_announced_nothing_at_all_cannot_show_a_form() -> None:
    class Session:
        client_capabilities = None

    class Ctx:
        session = Session()

    assert approval._can_show_a_form(Ctx()) is False  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("elicitation", "expected"),
    [
        (None, False),
        (mcp_types.ElicitationCapability(), True),
        (
            mcp_types.ElicitationCapability(form=mcp_types.FormElicitationCapability()),
            True,
        ),
        (
            mcp_types.ElicitationCapability(
                form=mcp_types.FormElicitationCapability(),
                url=mcp_types.UrlElicitationCapability(),
            ),
            True,
        ),
        (
            mcp_types.ElicitationCapability(url=mcp_types.UrlElicitationCapability()),
            False,
        ),
    ],
)
def test_which_announced_capabilities_mean_a_form_can_be_shown(
    elicitation: mcp_types.ElicitationCapability | None, expected: bool
) -> None:
    assert _form(elicitation) is expected


def test_a_binding_changes_with_the_tool_the_arguments_and_the_state() -> None:
    base = binding("block_user", {"usernames": ["bob"]}, [{"deny": False}])
    assert base == binding("block_user", {"usernames": ["bob"]}, [{"deny": False}])
    assert (
        base.args_hash != binding("delete_user", {"usernames": ["bob"]}, []).args_hash
    )
    assert base.args_hash != binding("block_user", {"usernames": ["eve"]}, []).args_hash
    other_state = binding("block_user", {"usernames": ["bob"]}, [{"deny": True}])
    assert base.args_hash == other_state.args_hash
    assert base.state_hash != other_state.state_hash
    assert len(base.args_hash) == len(base.state_hash) == 64


def test_a_binding_does_not_depend_on_key_order_but_does_on_list_order() -> None:
    assert binding("t", {"a": 1, "b": 2}, {"x": 1, "y": 2}) == binding(
        "t", {"b": 2, "a": 1}, {"y": 2, "x": 1}
    )
    assert (
        binding("t", {"names": ["a", "b"]}, None).args_hash
        != binding("t", {"names": ["b", "a"]}, None).args_hash
    )
    assert canonical({"b": 1, "a": [True, None]}) == '{"a":[true,null],"b":1}'


def test_true_and_the_text_true_are_different_states() -> None:
    assert binding("t", {}, {"deny": True}) != binding("t", {}, {"deny": "true"})
    assert binding("t", {}, {"deny": False}) != binding("t", {}, {"deny": None})


# The 2026-07-28 era: round two, driven by hand.


async def first_round(
    client: Client, **arguments: Any
) -> mcp_types.InputRequiredResult:
    result = await client.session.call_tool(
        "change", arguments, allow_input_required=True
    )
    assert isinstance(result, mcp_types.InputRequiredResult)
    return result


async def second_round(
    client: Client,
    state: str | None,
    responses: Any = None,
    **arguments: Any,
) -> str:
    result = await client.session.call_tool(
        "change",
        arguments,
        input_responses=YES if responses is None else responses,
        request_state=state,
        allow_input_required=True,
    )
    assert isinstance(result, mcp_types.CallToolResult), result
    return result.structured_content["decision"]


def modern(mcp: FastMCP) -> Client:
    return Client(
        mcp, mode="2026-07-28", elicitation_handler=elicitation_handler("accept")
    )


async def test_the_first_round_asks_with_the_text_and_a_yes_no_form() -> None:
    mcp, _ = server()
    async with modern(mcp) as client:
        asked = await first_round(client)
    request = asked.input_requests["approve"]
    assert request.params.message == TEXT
    assert request.params.requested_schema == {
        "type": "object",
        "properties": {"approve": {"type": "boolean", "title": "Apply this change?"}},
        "required": ["approve"],
    }
    assert asked.request_state and len(approval._issued) == 1


async def test_the_state_on_the_wire_is_sealed_not_readable_json() -> None:
    """The framework seals request_state; the hashes and the nonce are not shown to
    the client, and a state the client made up is refused before the tool runs."""
    mcp, world = server()
    async with modern(mcp) as client:
        asked = await first_round(client)
        with pytest.raises(ValueError):
            json.loads(asked.request_state)
        nonce = next(iter(approval._issued))
        forged = json.dumps({"args": "x", "state": "y", "nonce": nonce})
        with pytest.raises(Exception, match=r"(?i)state"):
            await second_round(client, forged)
    assert world["asked"] == 1


async def test_a_yes_in_the_second_round_is_approved() -> None:
    mcp, _ = server()
    async with modern(mcp) as client:
        asked = await first_round(client)
        assert await second_round(client, asked.request_state) == "APPROVED"
    assert approval._issued == {}


async def test_an_answer_for_other_arguments_is_not_an_approval() -> None:
    """The framework ties the sealed state to the request and refuses it before the
    tool runs; `ask` checks the arguments again (next test) in case it ever does
    not."""
    mcp, world = server()
    async with modern(mcp) as client:
        asked = await first_round(client, target="bob")
        with pytest.raises(MCPError, match="requestState"):
            await second_round(client, asked.request_state, target="eve")
        assert world["asked"] == 1
        # and the prompt for bob is still good for bob
        assert await second_round(client, asked.request_state, target="bob") == (
            "APPROVED"
        )


class FakeContext:
    """What `ask` reads from the context in the second round, with a state the
    framework did not check."""

    def __init__(self, state: str | None, responses: Any = YES) -> None:
        self.input_responses = responses
        self.request_state = state

    class request_context:
        protocol_version = "2026-07-28"


def issued_state(bind: Binding, **overrides: Any) -> str:
    approval._issued["n-1"] = None
    state = {"args": bind.args_hash, "state": bind.state_hash, "nonce": "n-1"}
    return json.dumps({**state, **overrides})


async def test_ask_itself_refuses_a_state_made_for_other_arguments() -> None:
    bob = binding("change", {"target": "bob"}, {"deny": False})
    eve = binding("change", {"target": "eve"}, {"deny": False})
    assert await ask(FakeContext(issued_state(bob)), "prompt", TEXT, bob) == (  # type: ignore[arg-type]
        Decision.APPROVED
    )
    decision = await ask(FakeContext(issued_state(bob)), "prompt", TEXT, eve)  # type: ignore[arg-type]
    assert decision == Decision.CANCELLED
    # a refusal for the wrong arguments does not use up bob's prompt
    assert "n-1" in approval._issued


@pytest.mark.parametrize(
    "state",
    [
        None,
        "",
        "not json",
        "[]",
        '"text"',
        "{}",
        '{"args": 1, "state": 2, "nonce": 3}',
        '{"args": "a", "state": "s"}',
    ],
)
async def test_ask_refuses_a_state_it_cannot_read(state: str | None) -> None:
    bind = binding("change", {}, None)
    decision = await ask(FakeContext(state), "prompt", TEXT, bind)  # type: ignore[arg-type]
    assert decision == Decision.CANCELLED


async def test_ask_refuses_a_nonce_it_never_issued() -> None:
    bind = binding("change", {}, None)
    state = json.dumps(
        {"args": bind.args_hash, "state": bind.state_hash, "nonce": "made-up"}
    )
    decision = await ask(FakeContext(state), "prompt", TEXT, bind)  # type: ignore[arg-type]
    assert decision == Decision.CANCELLED


async def test_an_answer_after_the_server_state_changed_is_stale() -> None:
    mcp, world = server()
    async with modern(mcp) as client:
        asked = await first_round(client)
        world["state"] = {"deny": True}
        assert await second_round(client, asked.request_state) == "STALE"
        # a stale prompt is used up: the admin has to see the new state
        world["state"] = {"deny": False}
        assert await second_round(client, asked.request_state) == "CANCELLED"


async def test_an_approval_state_is_accepted_once() -> None:
    mcp, _ = server()
    async with modern(mcp) as client:
        asked = await first_round(client)
        assert await second_round(client, asked.request_state) == "APPROVED"
        assert await second_round(client, asked.request_state) == "CANCELLED"


async def test_a_refusal_also_uses_the_prompt_up() -> None:
    mcp, _ = server()
    no = {"approve": mcp_types.ElicitResult(action="decline")}
    async with modern(mcp) as client:
        asked = await first_round(client)
        assert await second_round(client, asked.request_state, no) == "CANCELLED"
        assert await second_round(client, asked.request_state) == "CANCELLED"


async def test_an_answer_without_a_state_is_not_an_approval() -> None:
    mcp, _ = server()
    async with modern(mcp) as client:
        await first_round(client)
        assert await second_round(client, None) == "CANCELLED"


async def test_a_state_issued_before_a_server_restart_is_not_an_approval() -> None:
    mcp, _ = server()
    async with modern(mcp) as client:
        asked = await first_round(client)
        approval._issued.clear()
        assert await second_round(client, asked.request_state) == "CANCELLED"


@pytest.mark.parametrize(
    "responses",
    [
        {
            "approve": mcp_types.ElicitResult(
                action="accept", content={"approve": False}
            )
        },
        {"approve": mcp_types.ElicitResult(action="accept", content={})},
        {"approve": mcp_types.ElicitResult(action="accept")},
        {
            "approve": mcp_types.ElicitResult(
                action="accept", content={"approve": "true"}
            )
        },
        {"approve": mcp_types.ElicitResult(action="accept", content={"approve": 1})},
        {"approve": mcp_types.ElicitResult(action="accept", content={"other": True})},
        {
            "approve": mcp_types.ElicitResult(
                action="decline", content={"approve": True}
            )
        },
        {"approve": mcp_types.ElicitResult(action="cancel", content={"approve": True})},
        {"other": mcp_types.ElicitResult(action="accept", content={"approve": True})},
        {},
    ],
)
async def test_only_accept_with_a_real_true_under_the_right_key_is_a_yes(
    responses: dict,
) -> None:
    mcp, _ = server()
    async with modern(mcp) as client:
        asked = await first_round(client)
        assert await second_round(client, asked.request_state, responses) == (
            "CANCELLED"
        )


async def test_two_prompts_are_answered_independently() -> None:
    mcp, _ = server()
    async with modern(mcp) as client:
        for_bob = await first_round(client, target="bob")
        for_eve = await first_round(client, target="eve")
        assert await second_round(client, for_eve.request_state, target="eve") == (
            "APPROVED"
        )
        assert await second_round(client, for_bob.request_state, target="bob") == (
            "APPROVED"
        )


async def test_unanswered_prompts_do_not_pile_up_without_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(approval, "MAX_PENDING", 3)
    mcp, _ = server()
    async with modern(mcp) as client:
        oldest = await first_round(client)
        for _ in range(3):
            newest = await first_round(client)
        assert len(approval._issued) == 3
        assert await second_round(client, oldest.request_state) == "CANCELLED"
        assert await second_round(client, newest.request_state) == "APPROVED"


def test_a_binding_is_two_hashes_and_nothing_else() -> None:
    assert set(Binding.__dataclass_fields__) == {"args_hash", "state_hash"}
