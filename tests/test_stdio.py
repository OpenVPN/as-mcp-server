"""Over stdio the server must write nothing but JSON-RPC to stdout.

Logs go to stderr and never contain secrets.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from pathlib import Path

from as_mcp_server import __version__
from tests.test_server import EXPECTED_TOOLS

PASSWORD_MARKER = "stdio-marker-s3cret"
INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "stdio-contract-test", "version": "0"},
    },
}
INITIALIZED = {"jsonrpc": "2.0", "method": "notifications/initialized"}
TOOLS_LIST = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}


def _talk(process: subprocess.Popen[str], messages: list[dict]) -> list[str]:
    """Send each message; after a request, read stdout until its response arrives.

    Closing stdin right after writing (subprocess.run with input=...) makes the
    server stop on EOF and drop requests still in flight, so stdin stays open until
    the last response has been read.
    """
    assert process.stdin is not None and process.stdout is not None
    lines: list[str] = []
    for message in messages:
        process.stdin.write(json.dumps(message) + "\n")
        process.stdin.flush()
        if "id" not in message:
            continue
        while True:
            line = process.stdout.readline()
            if not line:
                return lines  # the server exited (or the watchdog killed it)
            if line.strip():
                lines.append(line)
            try:
                if json.loads(line).get("id") == message["id"]:
                    break
            except ValueError:
                continue  # not JSON: kept in lines, the assertions report it
    return lines


def test_stdout_is_only_jsonrpc_and_lists_the_thirteen_tools(tmp_path: Path) -> None:
    env = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith("OPENVPN_AS_")
    }
    # Nothing listens on port 9; tools/list needs no login, so no request is made.
    env.update(
        {
            "OPENVPN_AS_URL": "https://127.0.0.1:9",
            "OPENVPN_AS_USER": "openvpn",
            "OPENVPN_AS_PASSWORD": PASSWORD_MARKER,
            "OPENVPN_AS_CONFIG_DIR": str(tmp_path),
            "OPENVPN_AS_LOG_LEVEL": "DEBUG",
            "OPENVPN_AS_INSECURE": "true",
        }
    )
    process = subprocess.Popen(
        [sys.executable, "-m", "as_mcp_server"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    assert process.stdin is not None
    assert process.stdout is not None and process.stderr is not None
    stderr_chunks: list[str] = []
    drain = (
        threading.Thread(  # keep stderr flowing so DEBUG logs cannot block the server
            target=lambda: stderr_chunks.append(process.stderr.read()),  # type: ignore[union-attr]
            daemon=True,
        )
    )
    drain.start()
    watchdog = threading.Timer(90, process.kill)
    watchdog.start()
    try:
        lines = _talk(process, [INITIALIZE, INITIALIZED, TOOLS_LIST])
        process.stdin.close()
        rest = process.stdout.read()  # until the server exits on EOF
        process.wait(timeout=60)
    finally:
        watchdog.cancel()
        if process.poll() is None:
            process.kill()
            process.wait()
    drain.join(timeout=10)
    stderr = "".join(stderr_chunks)
    lines += [line for line in rest.splitlines() if line.strip()]
    assert lines, f"no stdout; stderr was:\n{stderr}"
    # Anything on stdout that is not JSON fails here.
    parsed = [json.loads(line) for line in lines]
    assert all(message.get("jsonrpc") == "2.0" for message in parsed)
    by_id = {message["id"]: message for message in parsed if "id" in message}
    assert by_id[1]["result"]["serverInfo"]["name"] == "as-mcp-server"
    assert by_id[1]["result"]["serverInfo"]["version"] == __version__
    assert {tool["name"] for tool in by_id[2]["result"]["tools"]} == EXPECTED_TOOLS
    assert PASSWORD_MARKER not in "".join(lines)
    assert PASSWORD_MARKER not in stderr
    assert "INSECURE" in stderr  # the startup warning is loud, and on stderr
