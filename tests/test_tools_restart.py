"""warm_restart: the one tool that restarts Access Server. It asks every time, also
in automatic approval mode, and says how many VPN clients are connected."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastmcp.exceptions import ToolError

from as_mcp_server import approval, tools_restart
from as_mcp_server.server import build
from as_mcp_server.settings import Settings
from as_mcp_server.texts import MSG_CANCELLED, MSG_RESTART_NEEDS_PROMPT, NOTE_RESTARTED
from tests.conftest import LOGIN, MODES, Router, call_tool
from tests.conftest import load_fixture as fixture
from tests.test_effective import own as own_value
from tests.test_effective import record
from tests.test_tools_sessions import session
from tests.test_writes import users_route

pytestmark = pytest.mark.usefixtures("clean_env")

RESTART = ("POST", "/api/server/restart")
OLD, NEW = "2026-11-18T08:00:00.000000Z", "2026-11-18T19:30:00.000000Z"


@pytest.fixture(autouse=True)
def no_waiting(monkeypatch: pytest.MonkeyPatch):
    approval._issued.clear()
    monkeypatch.setattr(tools_restart, "POLL_SECONDS", 0)
    monkeypatch.setattr(tools_restart, "SETTLE_POLLS", 3)
    yield
    approval._issued.clear()


class FakeServer:
    def __init__(self, tmp_path: Path, *, mode: str = "prompt") -> None:
        self.tmp_path = tmp_path
        self.restarted = OLD
        self.sessions = [session("alice"), session("bob", client_id=1)]
        self.answer: tuple[int, Any] = (200, {})
        self.moves_the_time = True
        self.queries: list[str] = []
        users = [record("openvpn", admin=own_value(True))]
        self.router = Router(
            {
                LOGIN: fixture("login_ok"),
                ("GET", "/api/server/info"): fixture("server_info"),
                ("POST", "/api/users/list"): users_route(users),
                ("POST", "/api/groups/list"): users_route([]),
                ("GET", "/api/vpn/status"): lambda request: httpx.Response(
                    200, json={"vpn_clients": self.sessions, "vpn_daemons": {}}
                ),
                ("GET", "/api/server/status"): lambda request: httpx.Response(
                    200, json={"last_restarted": self.restarted, "service_status": {}}
                ),
                RESTART: self._restart,
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

    def _restart(self, request: httpx.Request) -> httpx.Response:
        self.queries.append(request.url.query.decode())
        status, body = self.answer
        if status == 200 and self.moves_the_time:
            self.restarted = NEW
        return httpx.Response(status, json=body)

    async def call(self, **options: Any) -> Any:
        return await call_tool(self.mcp, "warm_restart", {}, **options)

    def audit(self) -> list[dict[str, Any]]:
        path = self.tmp_path / "audit.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text("utf-8").splitlines()]


@pytest.mark.parametrize("mode", MODES)
async def test_an_approved_restart_is_sent_once_and_read_back(
    tmp_path: Path, mode: str
) -> None:
    server = FakeServer(tmp_path)
    seen: list[str] = []
    result = await server.call(mode=mode, seen=seen)
    assert server.queries == ["restartMode=warm"]
    assert seen == [
        "Server: https://as.example:943\n"
        "Action: Warm restart (1 item): Access Server\n"
        "Total: 2 connected VPN clients can be disconnected and have to reconnect, "
        "groups created since the last restart start to work\n"
        "\n"
        "- Access Server\n"
        f"    last restart: {OLD} -> now\n"
        "    also: 2 connected VPN client(s) can be disconnected and have to "
        "reconnect\n"
        "    also: groups created since the last restart start to work"
    ]
    (item,) = result["items"]
    assert item["outcome"] == "done"
    assert item["before"] == {"last_restarted": OLD}
    assert item["after"] == {"last_restarted": NEW}
    assert item["clients_connected_before"] == 2
    assert result["notes"] == [NOTE_RESTARTED]
    (line,) = server.audit()
    assert line["tool"] == "warm_restart" and line["outcome"] == "applied"


async def test_automatic_mode_still_asks_and_a_no_restarts_nothing(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path, mode="auto")
    seen: list[str] = []
    with pytest.raises(ToolError) as error:
        await server.call(answer="decline", seen=seen)
    assert str(error.value) == MSG_CANCELLED
    assert len(seen) == 1 and server.queries == []
    (line,) = server.audit()
    assert line["outcome"] == "cancelled" and line["approval"] == "prompt"


async def test_automatic_mode_restarts_after_a_yes(tmp_path: Path) -> None:
    server = FakeServer(tmp_path, mode="auto")
    result = await server.call()
    assert server.queries == ["restartMode=warm"]
    assert result["approval"] == "prompt"


@pytest.mark.parametrize("approval_mode", ["prompt", "auto"])
async def test_an_app_that_cannot_ask_cannot_restart(
    tmp_path: Path, approval_mode: str
) -> None:
    server = FakeServer(tmp_path, mode=approval_mode)
    with pytest.raises(ToolError) as error:
        await server.call(answer="none")
    assert str(error.value) == MSG_RESTART_NEEDS_PROMPT
    assert "OPENVPN_AS_APPROVAL" not in str(error.value)
    assert server.queries == []
    (line,) = server.audit()
    assert line["outcome"] == "refused_no_approval"


async def test_no_connected_client_is_said_in_the_list_and_left_out_of_the_totals(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    server.sessions = []
    seen: list[str] = []
    await server.call(seen=seen)
    lines = seen[0].splitlines()
    assert lines[2] == "Total: groups created since the last restart start to work"
    assert (
        "    also: 0 connected VPN client(s) can be disconnected and have to reconnect"
    ) in lines


async def test_a_restart_the_server_refuses_is_reported_as_failed(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    server.answer = (400, {"reason": "nftables configuration has errors"})
    result = await server.call()
    (item,) = result["items"]
    assert item["outcome"] == "failed" and result["notes"] == []
    assert item["after"] is None
    (line,) = server.audit()
    assert line["outcome"] == "failed"


async def test_a_restart_time_that_does_not_move_is_partial_not_done(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    server.moves_the_time = False
    result = await server.call()
    (item,) = result["items"]
    assert item["outcome"] == "partial"
    assert "does not show a new restart time" in item["detail"]
    assert server.queries == ["restartMode=warm"]


async def test_a_restart_by_someone_else_during_the_prompt_is_a_changed_state(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)

    async def handler(message, response_type, params, context):
        server.restarted = NEW
        from fastmcp.client.elicitation import ElicitResult

        fields = params.requested_schema.get("properties", {})
        return ElicitResult(action="accept", content=dict.fromkeys(fields, True))

    from fastmcp import Client

    async with Client(server.mcp, mode="legacy", elicitation_handler=handler) as client:
        with pytest.raises(ToolError, match="Changed on the server"):
            await client.call_tool("warm_restart", {})
    assert server.queries == []
