"""Create the dev-stand fixtures the live tests expect, without opening the Admin UI.

Usage: uv run python dev/seed_fixtures.py [as-latest] [as-3-1-0]   (default: both)

Idempotent: objects that already exist are left alone. Needs the containers from
dev/compose.yaml running and dev/.local/<stand>.env with the admin credentials.
Users and the group are created through `docker exec <stand> sacli` (a group is a
user record with type=group and group_declare=true); the ruleset and its rules, the
connection profile of alice and the access list of the group go through the Web
API. The MFA admin is set up by hand, see dev/README.md.
"""

from __future__ import annotations

import asyncio
import json
import secrets
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / "dev" / ".local"
STANDS = ("as-latest", "as-3-1-0")
GROUP = "staff"
RULESET = {"name": "Staff web", "comment": "dev-stand fixture"}
CONTRACTORS = "contractors"
NON_LATIN_USER = "жанна"
# A plain user with a password: the live tests sign in as bob to see what a
# non-administrator gets. The password is generated once into NON_ADMIN_ENV.
NON_ADMIN = "bob"
NON_ADMIN_ENV = LOCAL / "non-admin.env"
PLAIN_USERS = ("alice", NON_ADMIN, NON_LATIN_USER)
MEMBERS = {
    GROUP: ("alice", "mfa-admin"),
    CONTRACTORS: (NON_ADMIN, NON_LATIN_USER),
}
# username -> comments of the userlogin profiles the stand must hold.
PROFILES = {
    "alice": ("dev-stand fixture",),
    NON_ADMIN: tuple(f"dev-stand fixture {n}" for n in (1, 2, 3, 4)),
    NON_LATIN_USER: ("dev-stand fixture",),
}


def _subnet(netip: str, prefix_length: int, *service: dict[str, Any]) -> dict[str, Any]:
    subnet: dict[str, Any] = {
        "ipv6": ":" in netip,
        "netip": netip,
        "prefix_length": prefix_length,
    }
    if service:
        subnet["service"] = list(service)
    return subnet


def _entry(owner: dict[str, str], kind: str, **route: Any) -> dict[str, Any]:
    return {**owner, "type": kind, "access_route": {"accept": True, **route}}


# One of every shape the access-list endpoint can return: route and nat, a deny
# entry, services (a port, a port range, an ICMP type), the user, group and
# all_vpn_clients classes, access_from, a non-Latin owner.
# The Web API refuses to write an IPv6 access list ("IPv6 support is not fully
# implemented yet", 3.1.0 and 3.2.4) and does not return one either, so this one is
# written with sacli; a live test checks that it stays invisible.
IPV6_PROP = (CONTRACTORS, "access_to_ipv6.0", "+ROUTE:fd00:20::/64")
ACCESS_ENTRIES = [
    _entry(
        {"groupname": GROUP},
        "access_to_ipv4",
        type="route",
        subnet=_subnet("10.20.0.0", 24),
    ),
    _entry(
        {"username": "alice"},
        "access_to_ipv4",
        type="nat",
        subnet=_subnet("10.30.0.5", 32),
    ),
    _entry(
        {"username": "alice"},
        "access_to_ipv4",
        type="route",
        subnet=_subnet(
            "10.40.0.0",
            24,
            {"protocol": "tcp", "start_port": 443},
            {"protocol": "udp", "start_port": 2000, "end_port": 2999},
            {"protocol": "icmp", "type": "icmp-echo-request"},
        ),
    ),
    _entry(
        {"username": "alice"},
        "access_to_ipv4",
        type="route",
        accept=False,
        subnet=_subnet("10.40.0.99", 32),
    ),
    _entry({"groupname": CONTRACTORS}, "access_to_ipv4", type="all_vpn_clients"),
    _entry({"username": NON_ADMIN}, "access_from_ipv4", type="user", username="alice"),
    _entry({"username": NON_ADMIN}, "access_to_ipv4", type="group", groupname=GROUP),
    _entry(
        {"username": NON_LATIN_USER},
        "access_to_ipv4",
        type="route",
        subnet=_subnet("10.50.0.0", 16),
    ),
]
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


def non_admin_password() -> str:
    """The password of NON_ADMIN, generated on first use and kept out of git."""
    if NON_ADMIN_ENV.exists():
        return read_env(NON_ADMIN_ENV)["OPENVPN_AS_PASSWORD"]
    password = secrets.token_urlsafe(18)
    NON_ADMIN_ENV.touch(mode=0o600)
    NON_ADMIN_ENV.write_text(
        f"OPENVPN_AS_USER={NON_ADMIN}\nOPENVPN_AS_PASSWORD={password}\n",
        encoding="utf-8",
    )
    return password


def bare(value: Any) -> Any:
    """An access-list entry without the empty fields the server adds on read."""
    if isinstance(value, dict):
        cleaned = {k: bare(v) for k, v in value.items()}
        return {k: v for k, v in cleaned.items() if v not in (None, [], {})}
    if isinstance(value, list):
        return [bare(v) for v in value]
    return value


def canonical(entries: list[dict[str, Any]]) -> list[str]:
    return sorted(json.dumps(entry, sort_keys=True) for entry in entries)


def owner_of(entry: dict[str, Any]) -> str:
    return entry.get("username") or entry["groupname"]


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

        for group in MEMBERS:
            if group in groups:
                log(f"group {group}: present")
            else:
                user_prop(stand, group, "type", "group")
                user_prop(stand, group, "group_declare", "true")
                log(f"group {group}: created")

        if RADIUS_USER in users:
            log(f"user {RADIUS_USER}: present")
        else:
            user_prop(stand, RADIUS_USER, "type", "user_compile")
            user_prop(stand, RADIUS_USER, "prop_superuser", "true")
            user_prop(stand, RADIUS_USER, "user_auth_type", "radius")
            log(f"user {RADIUS_USER}: created (admin bound to the radius service)")

        for user in PLAIN_USERS:
            if user in users:
                log(f"user {user}: present")
            else:
                user_prop(stand, user, "type", "user_connect")
                log(f"user {user}: created")
        if NON_ADMIN not in users or not NON_ADMIN_ENV.exists():
            sacli(
                stand,
                *("--user", NON_ADMIN, "--new_pass", non_admin_password()),
                "SetLocalPassword",
            )
            log(f"user {NON_ADMIN}: password set (dev/.local/{NON_ADMIN_ENV.name})")
        for group, members in MEMBERS.items():
            for member in members:
                if member == "mfa-admin" and member not in users:
                    log(f"user {member}: missing, create it by hand (dev/README.md)")
                    continue
                if users.get(member, {}).get("group") == group:
                    log(f"{member} in {group}: present")
                else:
                    user_prop(stand, member, "conn_group", group)
                    log(f"{member} in {group}: set")

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

        held = (await post("/profiles/list", {"page_size": 1000, "offset": 0}))[
            "profiles"
        ]
        for user, comments in PROFILES.items():
            have = {p["comment"] for p in held if p["username"] == user}
            for comment in comments:
                if comment in have:
                    continue
                # The answer is the profile itself (a private key); it is not kept.
                created = await http.post(
                    "/profiles/create",
                    json={
                        "username": user,
                        "profile_type": "userlogin",
                        "comment": comment,
                    },
                    headers=headers,
                )
                created.raise_for_status()
                log(f"connection profile of {user} ({comment!r}): created")
            log(f"connection profiles of {user}: {len(comments)} present")

        owner, key, value = IPV6_PROP
        props = json.loads(sacli(stand, "--user", owner, "UserPropGet"))
        if props.get(owner, {}).get(key) == value:
            log(f"IPv6 access list of {owner}: present")
        else:
            user_prop(stand, owner, key, value)
            log(f"IPv6 access list of {owner}: set with sacli")

        lists = (await post("/userprop/access/list", {}))["profiles"]
        for owner in dict.fromkeys(owner_of(e) for e in ACCESS_ENTRIES):
            wanted = [e for e in ACCESS_ENTRIES if owner_of(e) == owner]
            current = [bare(e) for e in lists if owner_of(e) == owner]
            if canonical(current) == canonical(wanted):
                log(f"access list of {owner}: present ({len(wanted)} entries)")
            else:
                await post("/userprop/access/set", {"items_set": wanted})
                log(f"access list of {owner}: set to {len(wanted)} entries")


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
