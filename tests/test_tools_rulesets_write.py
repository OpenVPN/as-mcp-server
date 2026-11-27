"""save_access_ruleset and delete_access_rulesets against an Access Server kept in
memory. What the fake does was measured on 3.1.0 and 3.2.4: /access/rulesets/list
shows only rule sets that have an owner, one row per owner; assigning the same rule
set to the same owner again moves it; a deleted rule set loses its owners and its
rules; an unknown id or owner is a 400."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastmcp.exceptions import ToolError

from as_mcp_server import approval
from as_mcp_server.server import build
from as_mcp_server.settings import Settings
from as_mcp_server.texts import (
    AUTO_ACCESS,
    MSG_AUTO_LIMIT,
    MSG_NO_SUCH_RULESET,
    NOTE_DOMAIN_RULES,
)
from as_mcp_server.tools_access_write import (
    MSG_DEFAULT_AS_OWNER,
    MSG_RULESET_NO_OWNER,
    MSG_RULESET_NOTHING,
    MSG_RULESET_USE_ASSIGN,
)
from tests.conftest import LOGIN, Router, body_of, call_tool
from tests.conftest import load_fixture as fixture
from tests.test_effective import own as own_value
from tests.test_effective import record
from tests.test_writes import users_route

pytestmark = pytest.mark.usefixtures("clean_env")

SERVER_INFO = ("GET", "/api/server/info")
USERS = ("POST", "/api/users/list")
GROUPS = ("POST", "/api/groups/list")
SETS = ("POST", "/api/access/rulesets/list")
ADD = ("POST", "/api/access/rulesets/add")
UPDATE = ("POST", "/api/access/rulesets/update")
DELETE = ("POST", "/api/access/rulesets/delete")
ASSIGN = ("POST", "/api/access/user-rulesets/modify")
RULES = ("POST", "/api/access/rules/list")
DEFAULT = "__DEFAULT__"


@pytest.fixture(autouse=True)
def no_pending_prompts():
    approval._issued.clear()
    yield
    approval._issued.clear()


def bad(reason: str) -> httpx.Response:
    return httpx.Response(400, json={"reason": reason})


class RuleSetServer:
    def __init__(self, tmp_path: Path, *, mode: str = "prompt") -> None:
        self.tmp_path = tmp_path
        self.users = [record("openvpn", admin=own_value(True)), record("alice")]
        self.groups = [record("staff")]
        self.sets: dict[int, dict[str, str]] = {
            1: {"name": "Staff web", "comment": "dev-stand fixture"}
        }
        self.owners: list[dict[str, Any]] = [
            {"owner": "staff", "owner_type": "group", "id": 1, "position": 100}
        ]
        self.rules: dict[int, list[dict]] = {1: fixture("access_rules")[1]["rules"]}
        self.next_id = 2
        # A path in here answers with this exception or (status, body) instead.
        self.fail: dict[tuple[str, str], Any] = {}
        status, info = fixture("server_info")
        handlers = {
            SETS: self._list,
            ADD: self._add,
            UPDATE: self._update,
            DELETE: self._delete,
            ASSIGN: self._assign,
            RULES: self._rules,
        }
        self.router = Router(
            {
                LOGIN: fixture("login_ok"),
                SERVER_INFO: (status, info),
                USERS: lambda request: users_route(self.users)(request),
                GROUPS: lambda request: users_route(self.groups)(request),
                **{
                    key: (
                        lambda request, key=key, handler=handler: self._or_fail(
                            key, handler, request
                        )
                    )
                    for key, handler in handlers.items()
                },
            }
        )
        settings = Settings(
            url="https://as.example:943",
            user="openvpn",
            password="write-test-password",
            config_dir=tmp_path,
            write_tools=True,
            approval=mode,  # type: ignore[arg-type]
        )
        self.mcp = build(settings, transport=self.router.transport())

    def _or_fail(self, key, handler, request: httpx.Request) -> httpx.Response:
        failure = self.fail.get(key)
        if isinstance(failure, Exception):
            raise failure
        if failure is not None:
            return httpx.Response(failure[0], json=failure[1])
        return handler(request)

    def _known(self, name: str) -> str | None:
        if name == DEFAULT:
            return DEFAULT
        if any(group["name"] == name for group in self.groups):
            return "group"
        if any(user["name"] == name for user in self.users):
            return "user_connect"
        return None

    def _list(self, request: httpx.Request) -> httpx.Response:
        owner = json.loads(request.content).get("owner")
        if owner is not None and self._known(owner) is None:
            return bad(f"Non-existent ruleset owner: {owner}")
        rows = [
            {**row, **self.sets[row["id"]]}
            for row in self.owners
            if owner is None or row["owner"] == owner
        ]
        return httpx.Response(200, json={"rulesets": rows})

    def _add(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        new = self.next_id
        self.next_id += 1
        self.sets[new] = {"name": body["name"], "comment": body["comment"]}
        self.rules[new] = []
        return httpx.Response(200, json={"id": new})

    def _update(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if body["id"] not in self.sets:
            return bad(f"Non-existent ruleset: {body['id']}")
        self.sets[body["id"]] = {"name": body["name"], "comment": body["comment"]}
        return httpx.Response(200)

    def _delete(self, request: httpx.Request) -> httpx.Response:
        ids = json.loads(request.content)["ids"]
        for gone in ids:
            if gone not in self.sets:
                return bad(f"Non-existent ruleset: {gone}")
        for gone in ids:
            del self.sets[gone], self.rules[gone]
        self.owners = [row for row in self.owners if row["id"] not in ids]
        return httpx.Response(200)

    def _assign(self, request: httpx.Request) -> httpx.Response:
        added = json.loads(request.content).get("add", {})
        for owner, wanted in added.items():
            if self._known(owner) is None:
                return bad(f"Non-existent subject name: {owner}")
            for entry in wanted:
                if entry["ruleset_id"] not in self.sets:
                    return bad(f"Non-existent ruleset: {entry['ruleset_id']}")
        for owner, wanted in added.items():
            for entry in wanted:
                self.owners = [
                    row
                    for row in self.owners
                    if (row["owner"], row["id"]) != (owner, entry["ruleset_id"])
                ]
                self.owners.append(
                    {
                        "owner": owner,
                        "owner_type": self._known(owner),
                        "id": entry["ruleset_id"],
                        "position": entry["position"],
                    }
                )
        return httpx.Response(200)

    def _rules(self, request: httpx.Request) -> httpx.Response:
        ids = json.loads(request.content)["ruleset_ids"]
        for wanted in ids:
            if wanted not in self.sets:
                return bad(f"Non-existent ruleset: {wanted}")
        rules = [rule for wanted in ids for rule in self.rules[wanted]]
        return httpx.Response(200, json={"rules": rules})

    def sent(self, key: tuple[str, str]) -> list[dict]:
        return [body_of(request) for request in self.router.sent(*key)]

    def writes(self) -> list[str]:
        paths = {ADD[1], UPDATE[1], DELETE[1], ASSIGN[1]}
        return [r.url.path for r in self.router.requests if r.url.path in paths]

    def audit(self) -> list[dict]:
        text = (self.tmp_path / "audit.jsonl").read_text("utf-8")
        return [json.loads(line) for line in text.splitlines()]

    async def save(self, args: dict[str, Any], **options: Any) -> Any:
        return await call_tool(self.mcp, "save_access_ruleset", args, **options)

    async def delete(self, ids: list[int], **options: Any) -> Any:
        return await call_tool(
            self.mcp, "delete_access_rulesets", {"ids": ids}, **options
        )


# --- save_access_ruleset: a new rule set -----------------------------------------


async def test_a_new_rule_set_is_created_and_assigned_in_one_approval(
    tmp_path: Path,
) -> None:
    server = RuleSetServer(tmp_path)
    seen: list[str] = []
    result = await server.save(
        {"name": "Web", "comment": "by the agent", "owners": ["alice", "staff"]},
        seen=seen,
    )
    (item,) = result["items"]
    assert item["outcome"] == "done", item
    assert item["id"] == 2
    assert server.sent(ADD) == [{"name": "Web", "comment": "by the agent"}]
    # One request for every owner; staff already has Staff web at 100.
    assert server.sent(ASSIGN) == [
        {
            "add": {
                "alice": [{"ruleset_id": 2, "position": 100}],
                "staff": [{"ruleset_id": 2, "position": 200}],
            }
        }
    ]
    assert item["after"] == {
        "id": 2,
        "name": "Web",
        "comment": "by the agent",
        "owners": ["alice (user) at position 100", "staff (group) at position 200"],
    }
    assert len(seen) == 1
    lines = seen[0].splitlines()
    assert lines[1] == "Action: Create rule set (1 item): Web"
    assert "    also: assigned to alice (user) at position 100" in lines
    assert "    also: assigned to staff (group) at position 200" in lines
    assert result["notes"] == [NOTE_DOMAIN_RULES]
    assert [line["outcome"] for line in server.audit()] == ["applied"]


async def test_a_new_rule_set_without_an_owner_is_refused(tmp_path: Path) -> None:
    server = RuleSetServer(tmp_path)
    with pytest.raises(ToolError) as error:
        await server.save({"name": "Web"})
    assert str(error.value) == MSG_RULESET_NO_OWNER
    assert server.writes() == []


async def test_all_users_is_sent_as_the_default_record(tmp_path: Path) -> None:
    server = RuleSetServer(tmp_path)
    seen: list[str] = []
    result = await server.save({"name": "Web", "all_users": True}, seen=seen)
    assert server.sent(ADD) == [{"name": "Web", "comment": ""}]
    assert server.sent(ASSIGN) == [
        {"add": {DEFAULT: [{"ruleset_id": 2, "position": 100}]}}
    ]
    assert result["items"][0]["after"]["owners"] == ["all users at position 100"]
    assert "    also: assigned to all users at position 100" in seen[0].splitlines()


async def test_typing_default_as_an_owner_is_refused(tmp_path: Path) -> None:
    server = RuleSetServer(tmp_path)
    with pytest.raises(ToolError) as error:
        await server.save({"name": "Web", "owners": [DEFAULT]})
    assert str(error.value) == MSG_DEFAULT_AS_OWNER
    assert server.writes() == []


async def test_an_unknown_owner_is_refused_before_any_write(tmp_path: Path) -> None:
    server = RuleSetServer(tmp_path)
    with pytest.raises(ToolError) as error:
        await server.save({"name": "Web", "owners": ["Alice"]})
    assert str(error.value) == (
        "There is no user or group named Alice on this Access Server (names are "
        "case-sensitive)."
    )
    assert server.writes() == []


async def test_a_given_position_is_used_for_every_owner(tmp_path: Path) -> None:
    server = RuleSetServer(tmp_path)
    await server.save({"name": "Web", "owners": ["alice", "staff"], "position": 50})
    assert server.sent(ASSIGN) == [
        {
            "add": {
                "alice": [{"ruleset_id": 2, "position": 50}],
                "staff": [{"ruleset_id": 2, "position": 50}],
            }
        }
    ]


async def test_a_position_another_rule_set_of_the_owner_has_is_refused(
    tmp_path: Path,
) -> None:
    server = RuleSetServer(tmp_path)
    with pytest.raises(ToolError) as error:
        await server.save({"name": "Web", "owners": ["staff"], "position": 100})
    assert str(error.value) == (
        "Refused: staff already has rule set Staff web (id 1) at position 100, and "
        "which of two rule sets at one position applies first is not known. Give "
        "another position."
    )
    assert server.writes() == []


async def test_an_owner_named_twice_is_refused(tmp_path: Path) -> None:
    server = RuleSetServer(tmp_path)
    with pytest.raises(ToolError) as error:
        await server.save({"name": "Web", "owners": ["alice", "alice"]})
    assert str(error.value) == "Refused: alice is in owners twice."


async def test_a_name_used_by_another_rule_set_is_said_in_the_question(
    tmp_path: Path,
) -> None:
    server = RuleSetServer(tmp_path)
    seen: list[str] = []
    await server.save({"name": "Staff web", "owners": ["alice"]}, seen=seen)
    assert (
        "    also: rule set 1 is also called Staff web; Access Server allows two "
        "rule sets with one name"
    ) in seen[0].splitlines()


async def test_a_comment_with_a_line_break_is_refused(tmp_path: Path) -> None:
    server = RuleSetServer(tmp_path)
    with pytest.raises(ToolError) as error:
        await server.save({"name": "Web", "comment": "a\nb", "owners": ["alice"]})
    assert str(error.value) == (
        "Refused: a comment is at most 200 printable characters on one line."
    )


async def test_a_failed_assignment_deletes_the_new_rule_set_again(
    tmp_path: Path,
) -> None:
    server = RuleSetServer(tmp_path)
    server.fail[ASSIGN] = (400, {"reason": "Non-existent subject name: alice"})
    result = await server.save({"name": "Web", "owners": ["alice"]})
    (item,) = result["items"]
    assert item["outcome"] == "failed"
    assert item["detail"] == (
        "Access Server rejected POST /access/user-rulesets/modify (400): "
        "Non-existent subject name: alice The new rule set 2 was deleted again; "
        "nothing was changed."
    )
    assert server.writes() == [ADD[1], ASSIGN[1], DELETE[1]]
    assert server.sent(DELETE) == [{"ids": [2]}]
    assert 2 not in server.sets
    assert [line["outcome"] for line in server.audit()] == ["failed"]


async def test_when_the_cleanup_fails_too_the_result_names_the_rule_set(
    tmp_path: Path,
) -> None:
    server = RuleSetServer(tmp_path)
    server.fail[ASSIGN] = (400, {"reason": "Non-existent subject name: alice"})
    server.fail[DELETE] = (500, {"reason": "busy"})
    result = await server.save({"name": "Web", "owners": ["alice"]})
    (item,) = result["items"]
    assert item["outcome"] == "partial"
    assert item["id"] == 2
    assert "rule set 2 has no owner" in item["detail"]
    assert "delete_access_rulesets" in item["detail"]
    assert item["detail"].endswith("(done: created)")


async def test_a_timeout_of_the_assignment_is_not_repeated(tmp_path: Path) -> None:
    server = RuleSetServer(tmp_path)
    server.fail[ASSIGN] = httpx.ReadTimeout("slow")
    result = await server.save({"name": "Web", "owners": ["alice"]})
    (item,) = result["items"]
    assert item["outcome"] == "unknown_after_timeout"
    assert server.writes() == [ADD[1], ASSIGN[1]]
    assert item["id"] == 2
    assert "rule set 2 has no owner" in item["detail"]


async def test_automatic_mode_refuses_rule_set_changes(tmp_path: Path) -> None:
    server = RuleSetServer(tmp_path, mode="auto")
    expected = MSG_AUTO_LIMIT.format(reason=AUTO_ACCESS)
    with pytest.raises(ToolError) as error:
        await server.save({"name": "Web", "owners": ["alice"]}, answer="none")
    assert str(error.value) == expected
    with pytest.raises(ToolError) as error:
        await server.save({"name": "Web", "ruleset_id": 1}, answer="none")
    assert str(error.value) == expected
    with pytest.raises(ToolError) as error:
        await server.delete([1], answer="none")
    assert str(error.value) == expected
    assert server.writes() == []
    assert [line["outcome"] for line in server.audit()] == ["refused_auto_limit"] * 3


# --- save_access_ruleset: rename -------------------------------------------------


async def test_rename_keeps_the_comment_when_none_is_given(tmp_path: Path) -> None:
    server = RuleSetServer(tmp_path)
    seen: list[str] = []
    result = await server.save({"name": "Staff sites", "ruleset_id": 1}, seen=seen)
    (item,) = result["items"]
    assert item["outcome"] == "done", item
    assert server.sent(UPDATE) == [
        {"id": 1, "name": "Staff sites", "comment": "dev-stand fixture"}
    ]
    assert item["before"]["name"] == "Staff web"
    assert item["after"] == {
        "id": 1,
        "name": "Staff sites",
        "comment": "dev-stand fixture",
        "owners": ["staff (group) at position 100"],
    }
    lines = seen[0].splitlines()
    assert lines[1] == "Action: Change rule set (1 item): Staff web (id 1)"
    assert "    name: Staff web -> Staff sites" in lines
    assert not any(line.startswith("    comment:") for line in lines)


async def test_a_new_comment_alone_is_written_with_the_name(tmp_path: Path) -> None:
    server = RuleSetServer(tmp_path)
    await server.save({"name": "Staff web", "ruleset_id": 1, "comment": ""})
    assert server.sent(UPDATE) == [{"id": 1, "name": "Staff web", "comment": ""}]


async def test_owners_with_a_rule_set_id_are_refused(tmp_path: Path) -> None:
    server = RuleSetServer(tmp_path)
    for extra in ({"owners": ["alice"]}, {"all_users": True}, {"position": 10}):
        with pytest.raises(ToolError) as error:
            await server.save({"name": "X", "ruleset_id": 1, **extra})
        assert str(error.value) == MSG_RULESET_USE_ASSIGN.format(id=1)
    assert server.writes() == []


async def test_a_rename_that_changes_nothing_is_refused(tmp_path: Path) -> None:
    server = RuleSetServer(tmp_path)
    with pytest.raises(ToolError) as error:
        await server.save({"name": "Staff web", "ruleset_id": 1})
    assert str(error.value) == MSG_RULESET_NOTHING.format(id=1)


async def test_rename_of_an_unknown_id_is_refused(tmp_path: Path) -> None:
    server = RuleSetServer(tmp_path)
    with pytest.raises(ToolError) as error:
        await server.save({"name": "X", "ruleset_id": 9})
    assert str(error.value) == MSG_NO_SUCH_RULESET.format(id=9)
    assert server.writes() == []


# --- delete_access_rulesets ------------------------------------------------------


async def test_delete_names_every_owner_and_the_rule_count(tmp_path: Path) -> None:
    server = RuleSetServer(tmp_path)
    server.owners.append(
        {"owner": DEFAULT, "owner_type": DEFAULT, "id": 1, "position": 300}
    )
    seen: list[str] = []
    result = await server.delete([1], seen=seen)
    (item,) = result["items"]
    assert item["outcome"] == "done", item
    assert item["target"] == "rule set 1"
    assert item["after"] == {"exists": False}
    assert server.sent(DELETE) == [{"ids": [1]}]
    lines = seen[0].splitlines()
    assert lines[1] == "Action: Delete rule set (1 item): Staff web (id 1)"
    assert "    rule set: exists -> deleted" in lines
    assert (
        "    also: owners that lose it: staff (group) at position 100, all users at "
        "position 300"
    ) in lines
    assert "    also: its 2 rules are deleted" in lines
    assert "    also: cannot be undone" in lines
    assert server.sets == {} and server.owners == []
    assert result["notes"] == [NOTE_DOMAIN_RULES]


async def test_delete_of_an_unknown_id_is_refused(tmp_path: Path) -> None:
    server = RuleSetServer(tmp_path)
    with pytest.raises(ToolError) as error:
        await server.delete([9])
    assert str(error.value) == MSG_NO_SUCH_RULESET.format(id=9)
    assert server.writes() == []


async def test_a_rule_set_without_an_owner_can_be_deleted(tmp_path: Path) -> None:
    server = RuleSetServer(tmp_path)
    server.sets[5] = {"name": "Lost", "comment": ""}
    server.rules[5] = []
    seen: list[str] = []
    result = await server.delete([5], seen=seen)
    assert result["items"][0]["outcome"] == "done"
    lines = seen[0].splitlines()
    assert lines[1] == "Action: Delete rule set (1 item): rule set 5"
    assert (
        "    also: it has no owner, so Access Server does not list it or its name"
    ) in lines
    assert "    also: it has no rules" in lines


async def test_two_rule_sets_are_deleted_one_request_each(tmp_path: Path) -> None:
    server = RuleSetServer(tmp_path)
    server.sets[5] = {"name": "Lost", "comment": ""}
    server.rules[5] = []
    result = await server.delete([1, 5])
    assert [item["outcome"] for item in result["items"]] == ["done", "done"]
    assert server.sent(DELETE) == [{"ids": [1]}, {"ids": [5]}]


async def test_a_rule_set_still_there_after_the_delete_is_a_partial_result(
    tmp_path: Path,
) -> None:
    server = RuleSetServer(tmp_path)
    server.fail[DELETE] = (200, None)
    result = await server.delete([1])
    (item,) = result["items"]
    assert item["outcome"] == "partial"
    assert item["detail"] == "Access Server still has rule set 1 (done: written)"
