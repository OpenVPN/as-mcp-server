"""The shared write flow, exercised with a stand-in tool over a dict in memory."""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from fastmcp import Client, Context, FastMCP
from fastmcp.client.elicitation import ElicitResult
from fastmcp.exceptions import ToolError
from mcp.server import request_state
from mcp.shared.exceptions import MCPError

from as_mcp_server import approval, texts
from as_mcp_server.audit import AuditError, AuditLog
from as_mcp_server.client import ClientHolder, RequestTimeoutError
from as_mcp_server.effective import UNKNOWN, CannotCompute
from as_mcp_server.guards import Effect
from as_mcp_server.preview import HIDDEN, PreviewItem
from as_mcp_server.settings import Settings
from as_mcp_server.texts import (
    MSG_AUTO_LIMIT,
    MSG_CANCELLED,
    MSG_CHANGED,
    MSG_LATE_ANSWER,
    MSG_LOCKOUT,
    MSG_NO_ELICITATION,
)
from as_mcp_server.versions import untested_refusal
from as_mcp_server.writes import (
    MAX_ITEMS,
    MSG_EARLIER_ITEMS_WRITTEN,
    MSG_INTERRUPTED,
    NOTE_LIVE,
    LateAnswer,
    Own,
    Partial,
    Plan,
    WriteDeps,
    read_group,
    read_user,
    run_write,
)
from tests.conftest import (
    LOGIN,
    MODES,
    Router,
    body_of,
    call_tool,
    elicitation_handler,
    load_fixture,
)
from tests.test_approval import YES
from tests.test_effective import own as own_value
from tests.test_effective import record

pytestmark = pytest.mark.usefixtures("clean_env")

SERVER_INFO = ("GET", "/api/server/info")
USERS = ("POST", "/api/users/list")
GROUPS = ("POST", "/api/groups/list")
ADMIN = {"admin": own_value(True)}
SAFE = {
    "deny": False,
    "deny_web": False,
    "admin": True,
    "auth_method": "local",
    "totp": False,
    "autologin": False,
    "group": None,
}
PLAIN = {**SAFE, "admin": False}


@pytest.fixture(autouse=True)
def no_pending_prompts():
    approval._issued.clear()
    yield
    approval._issued.clear()


class FakeOp:
    """A write tool over `world`: {name: {"value": ..., "counter": ...}}."""

    tool = "fake_change"
    action = "Change thing"
    note = NOTE_LIVE
    needs_output_dir = False

    def __init__(self, world: dict[str, dict[str, Any]]) -> None:
        self.world = world
        self.events: list[tuple[str, str]] = []
        self.applied: list[str] = []
        self.fail: set[str] = set()
        self.time_out: set[str] = set()
        self.partial: set[str] = set()
        self.crash: set[str] = set()
        self.lose_write: set[str] = set()
        self.cancel: set[str] = set()
        self.verify_crash: set[str] = set()
        self.verify_cancel: set[str] = set()
        self.slow = 0.0
        self.owns: list[Own] = []

    def key(self, item: dict[str, Any]) -> str:
        return item["name"].casefold()

    def target(self, item: dict[str, Any]) -> str:
        return item["name"]

    async def read(self, client: Any, item: dict[str, Any]) -> dict[str, Any]:
        self.events.append(("read", item["name"]))
        entry = self.world.get(item["name"])
        if entry is None:
            raise ToolError(f"There is no thing named {item['name']}.")
        return {"value": entry["value"]}  # the counter is not stable: left out

    def plan(self, item: dict[str, Any], before: dict[str, Any], own: Own) -> Plan:
        self.owns.append(own)
        if item.get("broken"):
            raise CannotCompute("the record has no readable deny")
        if item.get("invalid"):
            raise ToolError(f"Refused: {item['name']} cannot take that value.")
        effects: tuple[Effect, ...] = ()
        if "user_after" in item:
            start = SAFE if item["name"].casefold() == own.name.casefold() else PLAIN
            after = {
                **start,
                **{
                    field: UNKNOWN if value == "UNKNOWN" else value
                    for field, value in item["user_after"].items()
                },
            }
            effects = (Effect("user", item["name"], dict(start), after),)
        changes = {"value": (before["value"], item["value"])}
        if effects:
            changes.update(
                {
                    field: (effects[0].before[field], effects[0].after[field])
                    for field in item["user_after"]
                }
            )
        return Plan(
            PreviewItem(item["name"], changes),
            effects,
            auto_reason=item.get("auto_reason"),
            lockout=item.get("lockout"),
        )

    async def apply(
        self, client: Any, item: dict[str, Any], before: dict[str, Any]
    ) -> dict[str, Any]:
        name = item["name"]
        self.events.append(("apply", name))
        self.applied.append(name)
        if self.slow:
            await asyncio.sleep(self.slow)
        if name in self.fail:
            raise ToolError(f"Access Server refused the change of {name}.")
        if name in self.crash:
            raise RuntimeError("LEAK-internal detail")
        if name in self.time_out:
            self.world[name]["value"] = item["value"]  # it may have arrived
            raise RequestTimeoutError("Access Server did not answer in 30 s.")
        if name in self.partial:
            self.world[name]["value"] = item["value"]
            raise Partial(["created"], "the file could not be saved", {"serial": "7"})
        if name in self.cancel:
            self.world[name]["value"] = item["value"]  # the request was sent
            raise asyncio.CancelledError
        if name not in self.lose_write:
            self.world[name]["value"] = item["value"]
        return {"path": f"/out/{name}"} if item.get("with_path") else {}

    async def verify(self, client: Any, item: dict[str, Any]) -> dict[str, Any]:
        self.events.append(("verify", item["name"]))
        if item["name"] in self.verify_crash:
            raise KeyError("LEAK-missing field")
        if item["name"] in self.verify_cancel:
            raise asyncio.CancelledError
        state = {"value": self.world[item["name"]]["value"]}
        if state["value"] != item["value"]:
            raise Partial(["written"], "the server does not show the new value")
        return state


def users_route(records: list[dict], fail_from: int | None = None):
    """Answer /users/list in pages, and by name; fail every page from an offset."""

    def answer(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if "users" in body or "groups" in body:
            wanted = body.get("users") or body.get("groups")
            found = [r for r in records if r["name"] in wanted]
            return httpx.Response(200, json={"total": len(found), "profiles": found})
        offset, size = body["offset"], body["page_size"]
        if fail_from is not None and offset >= fail_from:
            return httpx.Response(500, json={"reason": "database is busy"})
        page = records[offset : offset + size]
        return httpx.Response(200, json={"total": len(records), "profiles": page})

    return answer


class Stand:
    def __init__(
        self,
        tmp_path: Path,
        *,
        mode: str = "prompt",
        user: str = "openvpn",
        users: list[dict] | None = None,
        groups: list[dict] | None = None,
        version: str | None = None,
        fail_users_from: int | None = None,
        world: dict[str, Any] | None = None,
    ) -> None:
        self.tmp_path = tmp_path
        users = (
            users
            if users is not None
            else [record("openvpn", **ADMIN), record("mfa-admin", **ADMIN)]
        )
        status, info = load_fixture("server_info")
        if version is not None:
            info = {**info, "version": version}
        self.router = Router(
            {
                LOGIN: load_fixture("login_ok"),
                SERVER_INFO: (status, info),
                USERS: users_route(users, fail_users_from),
                GROUPS: users_route(groups or []),
            }
        )
        settings = Settings(
            url="https://as.example:943",
            user=user,
            password="write-test-password",
            config_dir=tmp_path,
            write_tools=True,
            approval=mode,  # type: ignore[arg-type]
        )
        holder = ClientHolder(settings, transport=self.router.transport())
        self.deps = WriteDeps(holder, AuditLog(tmp_path))
        self.world = (
            world
            if world is not None
            else {
                name: {"value": 1, "counter": 0}
                for name in ("a", "b", "c", "openvpn", "mfa-admin")
            }
        )
        self.op = FakeOp(self.world)
        self.mcp = FastMCP("write-test")

        @self.mcp.tool
        async def fake_change(ctx: Context, items: list[dict[str, Any]]) -> Any:
            return await run_write(ctx, self.deps, self.op, items, {"items": items})

    async def call(
        self, items: list[dict[str, Any]], *, mode: str = "legacy", **options: Any
    ) -> dict[str, Any]:
        return await call_tool(
            self.mcp, "fake_change", {"items": items}, mode=mode, **options
        )

    def audit(self) -> list[dict[str, Any]]:
        path = self.tmp_path / "audit.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines()]

    def writes(self) -> list[tuple[str, str]]:
        return [event for event in self.op.events if event[0] != "read"]


def to(value: int, *names: str, **extra: Any) -> list[dict[str, Any]]:
    return [{"name": name, "value": value, **extra} for name in names]


def outcomes(result: dict[str, Any]) -> list[str]:
    return [item["outcome"] for item in result["items"]]


@pytest.mark.parametrize("mode", MODES)
async def test_an_approved_change_is_written_read_back_and_recorded(
    tmp_path: Path, mode: str
) -> None:
    stand = Stand(tmp_path)
    seen: list[str] = []
    result = await stand.call(to(2, "a"), mode=mode, seen=seen)
    assert result == {
        "tool": "fake_change",
        "approval": "prompt",
        "batch_id": None,
        "items": [
            {
                "target": "a",
                "outcome": "done",
                "before": {"value": 1},
                "after": {"value": 2},
                "detail": None,
            }
        ],
        "notes": [NOTE_LIVE],
    }
    assert seen == [
        "Server: https://as.example:943\n"
        "Action: Change thing (1 item): a\n"
        "\n"
        "- a\n"
        "    value: 1 -> 2"
    ]
    assert stand.world["a"]["value"] == 2 and stand.op.applied == ["a"]
    (line,) = stand.audit()
    assert line["outcome"] == "applied" and line["target"] == "a"
    assert line["before"] == {"value": 1} and line["after"] == {"value": 2}
    assert line["tool"] == "fake_change" and line["approval"] == "prompt"
    assert line["admin_user"] == "openvpn" and line["server_version"] == "3.2.4"
    assert line["server_url"] == "https://as.example:943"
    assert line["version_tested"] is True and line["batch_id"] is None


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("answer", ["no", "decline", "cancel"])
async def test_nothing_is_written_when_the_admin_declines(
    tmp_path: Path, mode: str, answer: str
) -> None:
    stand = Stand(tmp_path)
    with pytest.raises(ToolError) as refused:
        await stand.call(to(2, "a", "b"), mode=mode, answer=answer)
    assert str(refused.value) == MSG_CANCELLED
    assert stand.op.applied == [] and stand.world["a"]["value"] == 1
    lines = stand.audit()
    assert [line["outcome"] for line in lines] == ["cancelled", "cancelled"]
    assert [line["target"] for line in lines] == ["a", "b"]
    assert lines[0]["batch_id"] and lines[0]["batch_id"] == lines[1]["batch_id"]


@pytest.mark.parametrize("mode", MODES)
async def test_a_client_without_elicitation_gets_the_a1_message_and_no_write(
    tmp_path: Path, mode: str
) -> None:
    stand = Stand(tmp_path)
    with pytest.raises(ToolError) as refused:
        await stand.call(to(2, "a"), mode=mode, answer="none")
    assert str(refused.value) == MSG_NO_ELICITATION
    assert stand.op.applied == []
    assert [line["outcome"] for line in stand.audit()] == ["refused_no_approval"]


@pytest.mark.parametrize("mode", MODES)
async def test_auto_mode_writes_without_asking_and_says_so(
    tmp_path: Path, mode: str
) -> None:
    stand = Stand(tmp_path, mode="auto")
    seen: list[str] = []
    result = await stand.call(to(2, "a"), mode=mode, answer="cancel", seen=seen)
    assert result["approval"] == "auto" and outcomes(result) == ["done"]
    assert seen == [] and stand.world["a"]["value"] == 2
    assert stand.audit()[0]["approval"] == "auto"


async def test_one_bad_item_refuses_the_whole_list_before_any_write(
    tmp_path: Path,
) -> None:
    """Item 3 of 3 would block the own account."""
    stand = Stand(tmp_path)
    items = [*to(2, "a", "b"), *to(2, "openvpn", user_after={"deny": True})]
    seen: list[str] = []
    with pytest.raises(ToolError) as refused:
        await stand.call(items, seen=seen)
    assert str(refused.value) == MSG_LOCKOUT.format(name="openvpn")
    assert seen == [] and stand.op.applied == []
    lines = stand.audit()
    assert [line["outcome"] for line in lines] == ["refused_lockout"] * 3
    assert lines[2]["error"] == "the own account would be blocked"
    assert lines[2]["after"] == [
        {"kind": "user", "name": "openvpn", "after": {**SAFE, "deny": True}}
    ]


async def test_a_missing_target_refuses_the_whole_list_before_any_write(
    tmp_path: Path,
) -> None:
    stand = Stand(tmp_path)
    seen: list[str] = []
    with pytest.raises(ToolError, match="There is no thing named ghost"):
        await stand.call([*to(2, "a"), *to(2, "ghost"), *to(2, "b")], seen=seen)
    assert seen == [] and stand.op.applied == []
    lines = stand.audit()
    assert [line["outcome"] for line in lines] == ["failed"] * 3
    assert all("ghost" in line["error"] for line in lines)


async def test_an_item_the_tool_rejects_refuses_the_whole_list(tmp_path: Path) -> None:
    stand = Stand(tmp_path)
    with pytest.raises(ToolError, match="b cannot take that value"):
        await stand.call([*to(2, "a"), *to(2, "b", invalid=True)])
    assert stand.op.applied == []


async def test_a_broken_read_is_refused_in_every_mode(tmp_path: Path) -> None:
    for mode in ("prompt", "auto"):
        stand = Stand(tmp_path / mode, mode=mode)
        with pytest.raises(ToolError) as refused:
            await stand.call(to(2, "a", broken=True))
        assert "cannot be computed (the record has no readable deny)" in str(
            refused.value
        )
        assert stand.op.applied == []
        assert [line["outcome"] for line in stand.audit()] == ["failed"]


async def test_a_list_stops_at_the_first_failure_and_reports_every_item(
    tmp_path: Path,
) -> None:
    stand = Stand(tmp_path)
    stand.op.fail = {"b"}
    result = await stand.call(to(2, "a", "b", "c"))
    assert outcomes(result) == ["done", "failed", "not attempted"]
    assert result["items"][1]["detail"] == "Access Server refused the change of b."
    assert result["items"][2]["after"] is None
    assert stand.op.applied == ["a", "b"]
    assert stand.world["c"]["value"] == 1
    assert result["notes"] == [NOTE_LIVE]


async def test_a_timed_out_write_is_reported_and_never_repeated(tmp_path: Path) -> None:
    stand = Stand(tmp_path)
    stand.op.time_out = {"b"}
    result = await stand.call(to(2, "a", "b", "c"))
    assert outcomes(result) == ["done", "unknown_after_timeout", "not attempted"]
    assert stand.op.applied == ["a", "b"]
    timed_out = result["items"][1]
    assert "did not answer" in timed_out["detail"]
    assert "not repeated" in timed_out["detail"]
    assert timed_out["after"] == {"value": 2}  # the state read afterwards


async def test_a_timed_out_write_whose_state_cannot_be_read_has_no_after(
    tmp_path: Path,
) -> None:
    stand = Stand(tmp_path)
    stand.op.time_out = {"a"}
    stand.op.lose_write = {"a"}

    async def cannot_read(client: Any, item: dict[str, Any]) -> dict[str, Any]:
        raise RequestTimeoutError("Access Server did not answer in 30 s.")

    stand.op.verify = cannot_read  # type: ignore[method-assign]
    result = await stand.call(to(2, "a"))
    assert outcomes(result) == ["unknown_after_timeout"]
    assert result["items"][0]["after"] is None
    assert result["notes"] == []  # nobody knows whether anything is live


async def test_a_partial_item_names_the_steps_that_ran(tmp_path: Path) -> None:
    stand = Stand(tmp_path)
    stand.op.partial = {"a"}
    result = await stand.call(to(2, "a", "b"))
    assert outcomes(result) == ["partial", "not attempted"]
    item = result["items"][0]
    assert item["detail"] == "the file could not be saved (done: created)"
    assert item["serial"] == "7"  # what the admin needs to clean up
    assert item["after"] == {"value": 2}
    assert [line["outcome"] for line in stand.audit()] == ["partial"]
    assert result["notes"] == [NOTE_LIVE]


async def test_an_after_state_that_does_not_show_the_write_is_partial(
    tmp_path: Path,
) -> None:
    stand = Stand(tmp_path)
    stand.op.lose_write = {"a"}
    result = await stand.call(to(2, "a", "b"))
    assert outcomes(result) == ["partial", "not attempted"]
    assert result["items"][0]["detail"] == (
        "the server does not show the new value (done: written)"
    )


async def test_an_unexpected_error_in_one_item_is_reported_without_its_text(
    tmp_path: Path,
) -> None:
    stand = Stand(tmp_path)
    stand.op.crash = {"b"}
    result = await stand.call(to(2, "a", "b", "c"))
    assert outcomes(result) == ["done", "failed", "not attempted"]
    assert result["items"][1]["detail"] == (
        "Unexpected error (RuntimeError); see the server log."
    )
    assert "LEAK" not in json.dumps(result)
    assert "LEAK" not in (tmp_path / "audit.jsonl").read_text()
    assert [line["outcome"] for line in stand.audit()] == ["applied", "failed"]


def changing_handler(stand: Stand, name: str):
    """The admin says yes, but the thing changed while the prompt was open."""

    async def handler(message, response_type, params, context):
        stand.world[name]["value"] = 99
        fields = params.requested_schema.get("properties", {})
        return ElicitResult(action="accept", content=dict.fromkeys(fields, True))

    return handler


@pytest.mark.parametrize("mode", MODES)
async def test_a_change_on_the_server_after_the_preview_refuses_the_write(
    tmp_path: Path, mode: str
) -> None:
    stand = Stand(tmp_path)
    handler = changing_handler(stand, "a")
    async with Client(stand.mcp, mode=mode, elicitation_handler=handler) as client:
        with pytest.raises(ToolError) as refused:
            await client.call_tool("fake_change", {"items": to(2, "a", "b")})
    assert str(refused.value) == MSG_CHANGED
    assert stand.op.applied == [] and stand.world["b"]["value"] == 1
    assert [line["outcome"] for line in stand.audit()] == ["refused_changed"] * 2


async def test_a_later_item_that_changed_stops_the_list_there(tmp_path: Path) -> None:
    stand = Stand(tmp_path)
    handler = changing_handler(stand, "b")
    async with Client(stand.mcp, mode="legacy", elicitation_handler=handler) as client:
        result = (
            await client.call_tool("fake_change", {"items": to(2, "a", "b", "c")})
        ).structured_content
    assert outcomes(result) == ["done", "refused_changed", "not attempted"]
    assert result["items"][1]["detail"] == f"{MSG_CHANGED} {MSG_EARLIER_ITEMS_WRITTEN}"
    assert "repeat the call only for this item" in result["items"][1]["detail"]
    assert stand.op.applied == ["a"]
    assert [line["outcome"] for line in stand.audit()] == ["applied", "refused_changed"]


async def test_a_byte_counter_change_is_not_a_change(tmp_path: Path) -> None:
    stand = Stand(tmp_path)

    async def handler(message, response_type, params, context):
        stand.world["a"]["counter"] += 1000
        fields = params.requested_schema.get("properties", {})
        return ElicitResult(action="accept", content=dict.fromkeys(fields, True))

    for mode in MODES:
        async with Client(stand.mcp, mode=mode, elicitation_handler=handler) as client:
            result = (
                await client.call_tool("fake_change", {"items": to(mode, "a")})
            ).structured_content
        assert outcomes(result) == ["done"], mode


async def test_more_than_100_items_and_duplicates_are_refused(tmp_path: Path) -> None:
    stand = Stand(tmp_path)
    many = to(2, *(f"n{i}" for i in range(MAX_ITEMS + 1)))
    with pytest.raises(ToolError, match="101 items in one call; the limit is 100"):
        await stand.call(many)
    with pytest.raises(ToolError, match="b is in the list twice"):
        await stand.call([*to(2, "a"), *to(2, "B"), *to(2, "b")])
    with pytest.raises(ToolError, match="the list is empty"):
        await stand.call([])
    assert stand.op.events == []  # refused before any read
    assert stand.router.requests == []  # and before any request
    assert [line["target"] for line in stand.audit()] == ["101 items", "a", "B", "b"]


async def test_exactly_100_items_are_one_call_one_prompt(tmp_path: Path) -> None:
    names = [f"n{i}" for i in range(MAX_ITEMS)]
    stand = Stand(tmp_path, world={name: {"value": 1} for name in names})
    seen: list[str] = []
    result = await stand.call(to(2, *names), seen=seen)
    assert outcomes(result) == ["done"] * 100 and len(seen) == 1
    lines = stand.audit()
    assert len(lines) == 100 and len({line["batch_id"] for line in lines}) == 1
    assert len({line["change_id"] for line in lines}) == 100


@pytest.mark.parametrize("version", ["3.0.2", "beta", ""])
async def test_an_unsupported_server_version_refuses_writes(
    tmp_path: Path, version: str
) -> None:
    stand = Stand(tmp_path, version=version)
    with pytest.raises(ToolError, match=r"writes need Access Server 3\.1 or newer"):
        await stand.call(to(2, "a"))
    assert stand.op.events == []
    assert [line["outcome"] for line in stand.audit()] == ["failed"]


async def test_an_untested_server_version_warns_in_preview_result_and_audit(
    tmp_path: Path,
) -> None:
    stand = Stand(tmp_path, version="3.3.0")
    seen: list[str] = []
    result = await stand.call(to(2, "a"), seen=seen)
    warning = next(note for note in result["notes"] if "3.3" in note)
    assert "not on the tested list" in warning
    assert seen[0].endswith(f"\n\nWarning: {warning}")
    assert outcomes(result) == ["done"]
    (line,) = stand.audit()
    assert line["version_tested"] is False and line["server_version"] == "3.3.0"


@pytest.mark.parametrize("mode", ["prompt", "auto"])
async def test_an_op_that_refuses_untested_minors_writes_nothing_on_3_3(
    tmp_path: Path, mode: str
) -> None:
    stand = Stand(tmp_path, mode=mode, version="3.3.0")
    stand.op.refuse_untested = True
    seen: list[str] = []
    with pytest.raises(ToolError) as refused:
        await stand.call(to(2, "a"), seen=seen)
    assert str(refused.value) == untested_refusal("3.3.0")
    assert seen == [] and stand.op.events == []
    (line,) = stand.audit()
    assert line["outcome"] == "failed" and line["version_tested"] is False


async def test_an_op_that_refuses_untested_minors_writes_on_a_tested_one(
    tmp_path: Path,
) -> None:
    stand = Stand(tmp_path)
    stand.op.refuse_untested = True
    assert outcomes(await stand.call(to(2, "a"))) == ["done"]


async def test_two_parallel_writes_do_not_interleave(tmp_path: Path) -> None:
    stand = Stand(tmp_path, mode="auto")
    stand.op.slow = 0.02
    await asyncio.gather(stand.call(to(2, "a")), stand.call(to(2, "b")))
    order = stand.writes()
    assert order in (
        [("apply", "a"), ("verify", "a"), ("apply", "b"), ("verify", "b")],
        [("apply", "b"), ("verify", "b"), ("apply", "a"), ("verify", "a")],
    )
    for name in ("a", "b"):
        reads = [
            i for i, event in enumerate(stand.op.events) if event == ("read", name)
        ]
        apply = stand.op.events.index(("apply", name))
        assert len(reads) == 2 and reads[1] < apply  # read again right before writing
    first, second = order[0][1], order[2][1]
    events = stand.op.events
    assert events.index(("verify", first)) < events.index(("apply", second))
    reread_second = [i for i, e in enumerate(events) if e == ("read", second)][1]
    assert reread_second > events.index(("verify", first))


async def test_an_item_with_an_auto_reason_is_refused_in_auto_and_allowed_with_a_prompt(
    tmp_path: Path,
) -> None:
    items = to(2, "a", auto_reason="an autologin profile would be created")
    auto = Stand(tmp_path / "auto", mode="auto")
    with pytest.raises(ToolError) as refused:
        await auto.call(items)
    assert str(refused.value) == MSG_AUTO_LIMIT.format(
        reason="an autologin profile would be created"
    )
    assert auto.op.applied == []
    assert [line["outcome"] for line in auto.audit()] == ["refused_auto_limit"]
    prompt = Stand(tmp_path / "prompt")
    assert outcomes(await prompt.call(items)) == ["done"]


@pytest.mark.parametrize("mode", ["prompt", "auto"])
async def test_a_plan_lockout_refuses_in_every_mode_before_the_question(
    tmp_path: Path, mode: str
) -> None:
    """A lockout only the tool can see, such as a new password of the own account."""
    stand = Stand(tmp_path, mode=mode)
    items = [*to(2, "a"), *to(2, "b", lockout="the own password would change")]
    seen: list[str] = []
    with pytest.raises(ToolError) as refused:
        await stand.call(items, seen=seen)
    assert str(refused.value) == MSG_LOCKOUT.format(name="openvpn")
    assert seen == [] and stand.op.applied == []
    lines = stand.audit()
    assert [line["outcome"] for line in lines] == ["refused_lockout"] * 2
    assert {line["error"] for line in lines} == {"the own password would change"}


async def test_auto_mode_refuses_what_needs_a_person(tmp_path: Path) -> None:
    stand = Stand(tmp_path, mode="auto")
    with pytest.raises(ToolError) as refused:
        await stand.call([*to(2, "a"), *to(2, "b", user_after={"admin": True})])
    assert str(refused.value) == MSG_AUTO_LIMIT.format(
        reason="user b would become an administrator"
    )
    assert stand.op.applied == []


async def test_a_result_that_cannot_be_computed_is_refused_in_auto_mode(
    tmp_path: Path,
) -> None:
    stand = Stand(tmp_path, mode="auto")
    with pytest.raises(ToolError) as refused:
        await stand.call(to(2, "a", user_after={"totp": "UNKNOWN"}))
    assert str(refused.value) == MSG_AUTO_LIMIT.format(
        reason="the totp of user a after this change is not known"
    )
    assert stand.op.applied == []
    (line,) = stand.audit()
    assert line["outcome"] == "refused_auto_limit"
    assert line["after"][0]["after"]["totp"] == "unknown"


async def test_an_unknown_value_of_another_user_is_written_with_a_prompt_and_the_preview_says_so(  # noqa: E501
    tmp_path: Path,
) -> None:
    stand = Stand(tmp_path)
    seen: list[str] = []
    result = await stand.call(to(2, "a", user_after={"totp": "UNKNOWN"}), seen=seen)
    assert outcomes(result) == ["done"]
    assert "    totp: false -> inherited (server-wide value unknown)" in seen[0]


@pytest.mark.parametrize("mode", ["prompt", "auto"])
async def test_an_unknown_value_of_the_own_account_is_refused_with_a_prompt_too(
    tmp_path: Path, mode: str
) -> None:
    stand = Stand(tmp_path, mode=mode, world={"OpenVPN": {"value": 1}})
    seen: list[str] = []
    with pytest.raises(ToolError) as refused:
        await stand.call(
            to(2, "OpenVPN", user_after={"auth_method": "UNKNOWN"}), seen=seen
        )
    assert str(refused.value) == MSG_LOCKOUT.format(name="openvpn")
    assert seen == [] and stand.op.applied == []


async def test_the_own_account_is_the_one_the_client_is_signed_in_with(
    tmp_path: Path,
) -> None:
    stand = Stand(tmp_path, user="mfa-admin")
    with pytest.raises(ToolError) as refused:
        await stand.call(to(2, "mfa-admin", user_after={"deny": True}))
    assert str(refused.value) == MSG_LOCKOUT.format(name="mfa-admin")
    result = await stand.call(to(2, "openvpn", user_after={"deny": True}))
    assert outcomes(result) == ["done"]
    assert stand.audit()[-1]["admin_user"] == "mfa-admin"


async def test_the_own_state_reads_every_page_and_a_failed_page_makes_values_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("as_mcp_server.writes.PAGE_SIZE", 2)
    users = [record("openvpn", **ADMIN), *(record(f"u{i}") for i in range(5))]
    stand = Stand(tmp_path, users=users)
    assert outcomes(await stand.call(to(2, "a"))) == ["done"]
    own = stand.op.owns[-1]
    assert set(own.users) == {"openvpn", "u0", "u1", "u2", "u3", "u4"}
    assert own.base["totp"] is False and own.base["auth_method"] == "local"
    offsets = [body_of(r)["offset"] for r in stand.router.sent(*USERS)]
    assert offsets == [0, 2, 4]

    broken = Stand(tmp_path / "broken", users=users, fail_users_from=2, mode="auto")
    assert outcomes(await broken.call(to(3, "a"))) == ["done"]
    assert broken.op.owns[-1].base == {}  # nothing is known server-wide
    assert set(broken.op.owns[-1].users) == {"openvpn", "u0"}


async def test_a_users_list_that_does_not_answer_at_all_refuses_the_write(
    tmp_path: Path,
) -> None:
    stand = Stand(tmp_path, fail_users_from=0)
    with pytest.raises(ToolError, match="database is busy"):
        await stand.call(to(2, "a"))
    assert stand.op.applied == []


@pytest.mark.parametrize("mode", ["prompt", "auto"])
async def test_a_signed_in_account_without_a_user_record_refuses_every_write(
    tmp_path: Path, mode: str
) -> None:
    stand = Stand(tmp_path, mode=mode, users=[record("somebody-else")])
    with pytest.raises(ToolError) as refused:
        await stand.call(to(2, "a"))
    assert "the state of the signed-in account (openvpn) cannot be read" in str(
        refused.value
    )
    assert stand.op.events == []


async def test_the_own_account_is_found_in_any_letter_case(tmp_path: Path) -> None:
    stand = Stand(tmp_path, users=[record("OpenVPN", group="admins", **ADMIN)])
    assert outcomes(await stand.call(to(2, "a"))) == ["done"]
    own = stand.op.owns[-1]
    assert own.name == "OpenVPN" and own.group == "admins"


async def test_items_not_attempted_get_no_audit_line_and_done_is_written_as_applied(
    tmp_path: Path,
) -> None:
    stand = Stand(tmp_path)
    stand.op.fail = {"b"}
    await stand.call(to(2, "a", "b", "c"))
    lines = stand.audit()
    assert [(line["target"], line["outcome"]) for line in lines] == [
        ("a", "applied"),
        ("b", "failed"),
    ]
    assert lines[1]["error"] == "Access Server refused the change of b."
    assert lines[1]["after"] is None


async def test_every_item_gets_an_audit_line_with_a_shared_batch_id(
    tmp_path: Path,
) -> None:
    stand = Stand(tmp_path)
    result = await stand.call(to(2, "a", "b", "c"))
    lines = stand.audit()
    assert [line["target"] for line in lines] == ["a", "b", "c"]
    assert {line["batch_id"] for line in lines} == {result["batch_id"]}
    assert result["batch_id"] and len({line["change_id"] for line in lines}) == 3


async def test_extra_result_fields_of_the_tool_reach_the_result(tmp_path: Path) -> None:
    stand = Stand(tmp_path)
    result = await stand.call(to(2, "a", with_path=True))
    assert result["items"][0]["path"] == "/out/a"


async def test_an_audit_log_that_cannot_be_written_refuses_the_write(
    tmp_path: Path,
) -> None:
    stand = Stand(tmp_path)
    (tmp_path / "audit.jsonl").mkdir()
    with pytest.raises(ToolError, match=r"Cannot write the audit log"):
        await stand.call(to(2, "a"))
    assert stand.op.events == []


async def test_a_name_with_line_breaks_is_one_clean_target_everywhere(
    tmp_path: Path,
) -> None:
    name = "a\n- openvpn\n    deny: false -> true"
    stand = Stand(tmp_path, world={name: {"value": 1}})
    seen: list[str] = []
    result = await stand.call(to(2, name), seen=seen)
    shown = "a - openvpn deny: false -> true" + HIDDEN
    assert result["items"][0]["target"] == shown
    assert seen[0].count("\n- ") == 1
    assert stand.audit()[0]["target"] == shown


async def test_read_user_and_read_group_find_exact_names_only(tmp_path: Path) -> None:
    users = [record("alice", group="staff")]
    groups = [record("staff")]
    stand = Stand(tmp_path, users=users, groups=groups)
    client = stand.deps.holder.get()
    assert (await read_user(client, "alice"))["name"] == "alice"
    assert (await read_group(client, "staff", members=True))["name"] == "staff"
    sent = body_of(stand.router.sent(*GROUPS)[-1])
    assert sent["groups"] == ["staff"] and sent["enumerate_members"] is True
    with pytest.raises(ToolError, match=r"no user named Alice.*case-sensitive"):
        await read_user(client, "Alice")
    with pytest.raises(ToolError, match="staff is a group, not a user"):
        await read_user(client, "staff")
    with pytest.raises(ToolError, match="alice is a user, not a group"):
        await read_group(client, "alice")
    with pytest.raises(ToolError, match="__DEFAULT__ is the server's default record"):
        await read_user(client, "__DEFAULT__")
    with pytest.raises(ToolError, match="__DEFAULT__ is the server's default record"):
        await read_group(client, "__DEFAULT__")
    with pytest.raises(ToolError, match="no user named a b on this"):
        await read_user(client, "a\nb")


async def test_the_own_record_is_the_exact_name_when_names_differ_only_in_case(
    tmp_path: Path,
) -> None:
    users = [
        record("openvpn", **ADMIN),
        record("OpenVPN", group="staff"),
        record("OPENVPN"),
    ]
    stand = Stand(tmp_path, users=users, groups=[record("staff")])
    own = await stand.deps.own()
    assert own.name == "openvpn" and own.group is None
    assert own.user["admin"]["value"] is True


# --- a change that reached the server always leaves a trace -------------------------


@pytest.mark.parametrize("where", ["cancel", "verify_cancel"])
async def test_a_call_cancelled_during_the_write_still_gets_its_audit_line(
    tmp_path: Path, where: str
) -> None:
    stand = Stand(tmp_path, mode="auto")
    getattr(stand.op, where).add("b")
    with pytest.raises(BaseException) as error:
        await stand.call(to(2, "a", "b", "c"))
    assert not isinstance(error.value, AssertionError)
    assert stand.world["b"]["value"] == 2  # it did reach the server
    lines = stand.audit()
    assert [(line["target"], line["outcome"]) for line in lines] == [
        ("a", "applied"),
        ("b", "unknown_after_timeout"),
    ]
    assert lines[1]["error"] == MSG_INTERRUPTED
    assert stand.world["c"]["value"] == 1


async def test_an_unexpected_error_after_the_write_is_partial_and_audited(
    tmp_path: Path,
) -> None:
    stand = Stand(tmp_path)
    stand.op.verify_crash = {"a"}
    result = await stand.call(to(2, "a", "b"))
    assert outcomes(result) == ["partial", "not attempted"]
    detail = result["items"][0]["detail"]
    assert "Written, but the state afterwards could not be read" in detail
    assert "KeyError" in detail and "LEAK" not in json.dumps(result)
    assert [line["outcome"] for line in stand.audit()] == ["partial"]
    assert result["notes"] == [NOTE_LIVE]


async def test_after_a_timeout_the_result_says_what_the_check_found_missing(
    tmp_path: Path,
) -> None:
    stand = Stand(tmp_path)
    stand.op.time_out = {"a"}

    async def half_done(client: Any, item: dict[str, Any]) -> dict[str, Any]:
        raise Partial(["deny set"], "a session is still connected", {"hint": "x"})

    stand.op.verify = half_done  # type: ignore[method-assign]
    result = await stand.call(to(2, "a"))
    (item,) = result["items"]
    assert item["outcome"] == "unknown_after_timeout"
    assert "not repeated" in item["detail"]
    assert item["detail"].endswith("Read afterwards: a session is still connected.")
    assert item["after"] == {"value": 2} and item["hint"] == "x"
    assert stand.op.applied == ["a"]


async def test_a_record_that_cannot_be_read_is_a_refusal_with_an_audit_line(
    tmp_path: Path,
) -> None:
    stand = Stand(tmp_path)

    async def unreadable(client: Any, item: dict[str, Any]) -> dict[str, Any]:
        raise CannotCompute("the record has no readable deny")

    stand.op.read = unreadable  # type: ignore[method-assign]
    with pytest.raises(ToolError, match="cannot be computed"):
        await stand.call(to(2, "a"))
    assert [line["outcome"] for line in stand.audit()] == ["failed"]


async def test_a_failed_audit_write_does_not_hide_a_change_that_was_made(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stand = Stand(tmp_path, mode="auto")

    def refuse(**kwargs: Any) -> None:
        raise AuditError("Cannot write the audit log audit.jsonl: disk full.")

    monkeypatch.setattr(stand.deps.audit, "append", refuse)
    result = await stand.call(to(2, "a", "b"))
    assert outcomes(result) == ["done", "done"]
    assert stand.world["a"]["value"] == 2
    assert result["notes"] == [
        NOTE_LIVE,
        "Cannot write the audit log audit.jsonl: disk full.",
    ]


async def test_secret_keys_in_the_state_are_masked_in_the_result(
    tmp_path: Path,
) -> None:
    stand = Stand(tmp_path, mode="auto")

    async def with_secret(client: Any, item: dict[str, Any]) -> dict[str, Any]:
        return {"value": stand.world[item["name"]]["value"], "totp_secret": "LEAK"}

    stand.op.read = with_secret  # type: ignore[method-assign]
    stand.op.verify = with_secret  # type: ignore[method-assign]
    result = await stand.call(to(1, "a"))
    assert "LEAK" not in json.dumps(result)
    assert result["items"][0]["before"]["totp_secret"] == "<redacted>"
    assert result["items"][0]["after"]["totp_secret"] == "<redacted>"


def test_the_fixed_texts_are_the_ones_agreed_in_the_design() -> None:
    """Agents relay these word for word, and evals look for them: a reworded text
    is a behaviour change, so each one is written out here."""
    assert texts.MSG_CANCELLED == "Cancelled by the admin; nothing was changed."
    assert texts.MSG_NO_ELICITATION == (
        "Your AI app cannot show an approval prompt, so as-mcp-server did not make "
        "this change. Use an app that supports MCP elicitation, or set "
        "OPENVPN_AS_APPROVAL=auto in the MCP server settings to make changes without "
        "being asked."
    )
    assert texts.MSG_CHANGED == (
        "Changed on the server since the preview; nothing was written."
    )
    assert texts.MSG_LOCKOUT == (
        "Refused: this change would lock as-mcp-server out of its own admin account "
        "({name}). Make it in the Admin UI if it is really intended."
    )
    assert texts.MSG_AUTO_LIMIT == (
        "Refused in automatic approval mode: {reason}. Repeat it in an app that "
        "shows the approval prompt, or in the Admin UI."
    )
    assert texts.MSG_USE_BLOCK == (
        "Refused: use block_user to block a user; it also disconnects the user's "
        "sessions."
    )
    assert texts.MSG_NOT_DISCONNECTED == (
        "{name} is blocked but is not disconnected by this change; use "
        "disconnect_vpn_sessions."
    )
    assert texts.DEFAULT_REASON == "Disconnected through as-mcp-server"
    assert texts.CLIENT_REASON == "Disconnected by your administrator."
    assert texts.MSG_ONE_TARGET == "Give exactly one of {a} or {b}."


def test_the_fixed_texts_of_0_3_0_are_the_ones_in_the_plan() -> None:
    assert texts.MSG_USE_BLOCK_GROUP == (
        "Refused: use block_group to block a group; it also disconnects the members' "
        "sessions."
    )
    assert texts.AUTO_ACCESS == (
        "access rules and access lists are changed only after the approval question"
    )
    assert texts.AUTO_PASSWORD == "a password is reset only after the approval question"
    assert texts.AUTO_MFA == "MFA is reset only after the approval question"
    assert texts.MSG_UNTESTED_REFUSED == (
        "Refused: Access Server {server} is not on the tested list of as-mcp-server "
        "{mcp}, and access lists are changed only on tested versions. Make the change "
        "in the Admin UI."
    )
    assert texts.NOTE_ACCESS_LIST_RESTART == (
        "Saved. Access Server applies a changed access list only after a warm "
        "restart, which may briefly reconnect some users. Until then the old list "
        "applies. Ask the administrator before calling warm_restart."
    )
    assert texts.NOTE_DOMAIN_RULES == (
        "Saved. Domain rules apply without a restart, from the next connection of a "
        "user. They act on names that the device looks up through the DNS of the "
        "VPN; the address of the host itself is not opened."
    )
    assert texts.NOTE_DOMAIN_DENY == (
        "A domain rule with the action deny acts on the name only: it does not block "
        "the address of the host, and an access list that allows the address still "
        "lets the traffic through. To block an address, change the access list."
    )
    assert texts.MSG_LAST_OWNER == (
        "Refused: rule set {id} would have no owner left, and Access Server does not "
        "list such a rule set. Use delete_access_rulesets to remove it."
    )
    assert texts.MSG_DUPLICATE_ENTRY == (
        "Refused: the access list of {owner} already has {entry}."
    )
    assert texts.MSG_CONFLICT_ENTRY == (
        "Refused: the access list of {owner} already has {entry} with the opposite "
        "action. Remove it in the same call if the new entry should replace it."
    )
    assert texts.MSG_NOT_WRITABLE == (
        "Refused: the access list of {owner} holds {entry}, which the Web API cannot "
        "write back, and this change would have to rewrite it. Make the change in "
        "the Admin UI."
    )
    assert texts.MSG_NO_SUCH_ENTRY == (
        "Refused: the access list of {owner} has no entry {entry}."
    )
    assert texts.WARN_HIDDEN == (
        "{entry} has no effect: {earlier} comes first and matches the same traffic."
    )
    assert texts.MSG_GROUP_AND_REMOVE == (
        "Refused: give group or remove_from_group, not both."
    )
    assert texts.MSG_IN_NO_GROUP == "Refused: {name} is in no group."
    assert texts.MSG_NO_ACCESS_CHANGE == (
        "Refused: nothing to change. Give at least one entry to add or to remove."
    )
    assert texts.MSG_NO_MFA_TO_RESET == (
        "Refused: {name} has not set up MFA, so there is nothing to reset."
    )
    assert texts.MSG_MFA_NOT_ALLOWED == (
        "Refused: {name} signs in with {method}, which has no MFA of Access Server to "
        "reset."
    )
    assert texts.NOTE_PASSWORD_RESET == (
        "The old password stops working at once; a VPN session of the user stays "
        "connected."
    )
    assert texts.NOTE_MFA_RESET == "The user sets up MFA again at the next sign-in."
    assert texts.MSG_NO_SUCH_RULESET == "Refused: there is no rule set with id {id}."


async def test_a_late_answer_is_refused_in_plain_words_and_audited(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stand = Stand(tmp_path)
    stand.mcp.add_middleware(LateAnswer(stand.deps))
    arguments = {"items": to(2, "a")}
    handler = elicitation_handler("accept")
    options = {"mode": "2026-07-28", "elicitation_handler": handler}
    async with Client(stand.mcp, **options) as client:
        asked = await client.session.call_tool(
            "fake_change", arguments, allow_input_required=True
        )
        later = time.time() + 601
        monkeypatch.setattr(request_state, "time", SimpleNamespace(time=lambda: later))
        with pytest.raises(MCPError) as refused:
            await client.session.call_tool(
                "fake_change",
                arguments,
                input_responses=YES,
                request_state=asked.request_state,
                allow_input_required=True,
            )
    message = MSG_LATE_ANSWER.format(tool="fake_change")
    assert refused.value.error.message == message
    assert "more than 10 minutes" in message and "Nothing was changed" in message
    assert stand.op.applied == []
    (line,) = stand.audit()
    assert line["outcome"] == "refused_no_approval" and line["error"] == message
    assert line["tool"] == "fake_change" and '"a"' in line["target"]
    assert line["admin_user"] == "openvpn"


async def test_another_protocol_error_is_passed_on_unchanged(tmp_path: Path) -> None:
    stand = Stand(tmp_path)
    other = MCPError(code=-32602, message="Unknown tool", data={"reason": "other"})

    async def call_next(context: Any) -> Any:
        raise other

    context = SimpleNamespace(method="tools/call", message=None)
    with pytest.raises(MCPError) as refused:
        await LateAnswer(stand.deps).on_message(context, call_next)
    assert refused.value is other
    assert stand.audit() == []
