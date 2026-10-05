"""Create the dev-stand fixtures the live tests expect, without opening the Admin UI.

Usage: uv run python dev/seed_fixtures.py [as-3-2-2] [as-3-1-0]   (default: both)

Idempotent: objects that already exist are left alone. Needs the containers from
dev/compose.yaml running and dev/.local/<stand>.env with the admin credentials.
Users and the group are created through `docker exec <stand> sacli` (a group is a
user record with type=group and group_declare=true); the ruleset and its rules go
through the Web API. The MFA admin is set up by hand, see dev/README.md.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / "dev" / ".local"
STANDS = ("as-3-2-2", "as-3-1-0")
GROUP = "staff"
RULESET = {"name": "Staff web", "comment": "dev-stand fixture"}
RADIUS_USER = "radius-admin"
RADIUS_CONFIG = {
    "auth.radius.0.name": "dev-radius",
    "auth.radius.0.enable": "true",
    "auth.radius.0.auth_method": "pap",
    "auth.radius.0.server.0.host": "radius",
    "auth.radius.0.server.0.secret": "dev-radius-secret",
    "auth.radius.0.server.0.auth_port": "1812",
}
RULES = [
    {
        "type": "domain_routing",
        "match_type": "domain_or_subdomain",
        "match_data": "intranet.example.com",
        "action": "nat",
        "position": 100,
        "comment": "internal web via VPN",
    },
    {
        "type": "domain_routing",
        "match_type": "domain",
        "match_data": "blocked.example.com",
        "action": "deny",
        "position": 200,
        "comment": "blocked site",
    },
]


def read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


def sacli(stand: str, *args: str) -> str:
    result = subprocess.run(
        ["docker", "exec", stand, "sacli", *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def configure_radius(stand: str, log: Callable[[str], None]) -> None:
    """Point the stand at the dev FreeRADIUS container (compose service `radius`)."""
    current = json.loads(sacli(stand, "--pfilt", "auth.radius%", "ConfigQuery") or "{}")
    changed = [k for k, v in RADIUS_CONFIG.items() if current.get(k) != v]
    for key in changed:
        sacli(stand, "--key", key, "--value", RADIUS_CONFIG[key], "ConfigPut")
    if changed:
        sacli(stand, "start")
        log(f"radius back end: {len(changed)} keys set, services restarted")
    else:
        log("radius back end: present")


def user_prop(stand: str, user: str, key: str, value: str) -> None:
    subprocess.run(
        [
            *("docker", "exec", stand, "sacli"),
            *("--user", user, "--key", key, "--value", value),
            "UserPropPut",
        ],
        check=True,
        capture_output=True,
        text=True,
    )


async def seed(stand: str) -> None:
    env = read_env(LOCAL / f"{stand}.env")
    base = env["OPENVPN_AS_URL"].rstrip("/")

    def log(message: str) -> None:
        print(f"[{stand}] {message}")

    configure_radius(stand, log)
    await wait_for_api(base)
    async with httpx.AsyncClient(
        base_url=f"{base}/api", verify=False, timeout=30
    ) as http:
        login = await http.post(
            "/auth/login/userpassword",
            json={
                "request_admin": True,
                "username": env["OPENVPN_AS_USER"],
                "password": env["OPENVPN_AS_PASSWORD"],
            },
        )
        login.raise_for_status()
        headers = {"X-OpenVPN-As-AuthToken": login.json()["auth_token"]}

        async def post(path: str, body: dict[str, Any]) -> Any:
            response = await http.post(path, json=body, headers=headers)
            response.raise_for_status()
            # user-rulesets/modify and rules/modify answer 200 with an empty body
            return response.json() if response.content else None

        overview = await post("/helper/status-overview", {})
        if overview["eula_status"]["eula_accepted"]:
            log(
                "WARNING: the EULA is accepted (someone opened the Admin UI); "
                f"`docker exec {stand} sacli --key aui.eula_version ConfigDel` "
                "restores the pristine state the fixtures assume"
            )

        page = {"page_size": 100, "offset": 0}
        users = {p["name"]: p for p in (await post("/users/list", page))["profiles"]}
        groups = {g["name"] for g in (await post("/groups/list", page))["profiles"]}

        if GROUP in groups:
            log(f"group {GROUP}: present")
        else:
            user_prop(stand, GROUP, "type", "group")
            user_prop(stand, GROUP, "group_declare", "true")
            log(f"group {GROUP}: created")

        if RADIUS_USER in users:
            log(f"user {RADIUS_USER}: present")
        else:
            user_prop(stand, RADIUS_USER, "type", "user_compile")
            user_prop(stand, RADIUS_USER, "prop_superuser", "true")
            user_prop(stand, RADIUS_USER, "user_auth_type", "radius")
            log(f"user {RADIUS_USER}: created (admin bound to the radius service)")

        if "alice" in users:
            log("user alice: present")
        else:
            user_prop(stand, "alice", "type", "user_connect")
            log("user alice: created (no password; the tests never log in as alice)")
        for member in ("alice", "mfa-admin"):
            if member != "alice" and member not in users:
                log(f"user {member}: missing, create it by hand (dev/README.md)")
                continue
            if users.get(member, {}).get("group") == GROUP:
                log(f"{member} in {GROUP}: present")
            else:
                user_prop(stand, member, "conn_group", GROUP)
                log(f"{member} in {GROUP}: set")

        # /access/rulesets/list shows only rulesets that are assigned to an owner, so
        # a freshly added one is invisible until user-rulesets/modify: keep the id the
        # add call returns instead of looking the ruleset up again.
        assigned = (await post("/access/rulesets/list", {"owner": GROUP}))["rulesets"]
        ruleset = next((r for r in assigned if r["name"] == RULESET["name"]), None)
        if ruleset is None:
            created = await post("/access/rulesets/add", RULESET)
            ruleset = {"id": created["id"], "name": RULESET["name"]}
            log(f"ruleset {RULESET['name']!r}: created with id {ruleset['id']}")
            await post(
                "/access/user-rulesets/modify",
                {"add": {GROUP: [{"ruleset_id": ruleset["id"], "position": 100}]}},
            )
            log(f"ruleset {ruleset['id']} assigned to {GROUP} at position 100")
        else:
            log(f"ruleset {RULESET['name']!r} (id {ruleset['id']}): present")

        existing = await post("/access/rules/list", {"ruleset_ids": [ruleset["id"]]})
        present = {r["match_data"] for r in existing["rules"]}
        missing = [
            {**rule, "ruleset_id": ruleset["id"]}
            for rule in RULES
            if rule["match_data"] not in present
        ]
        if missing:
            await post("/access/rules/modify", {"add": missing})
            log(f"rules added: {[r['match_data'] for r in missing]}")
        else:
            log("rules: present")


async def wait_for_api(base: str) -> None:
    async with httpx.AsyncClient(verify=False, timeout=5) as http:
        for _ in range(60):
            try:
                await http.get(f"{base}/api/server/info")
                return
            except httpx.HTTPError:
                await asyncio.sleep(1)


async def main(stands: list[str]) -> int:
    failed: list[str] = []
    for stand in stands:
        if not (LOCAL / f"{stand}.env").exists():
            print(f"[{stand}] no dev/.local/{stand}.env, skipped", file=sys.stderr)
            continue
        try:
            await seed(stand)
        except Exception as exc:
            failed.append(stand)
            print(f"[{stand}] FAILED: {exc!r}", file=sys.stderr)
    if failed:
        print(f"seeding failed for: {', '.join(failed)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main(sys.argv[1:] or list(STANDS))))
