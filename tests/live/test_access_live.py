"""modify_access_list against both real servers. The traffic test reaches the hosts
of the probe network from an OpenVPN client; a changed access list applies only after
a warm restart, so that test restarts twice and is marked slow."""

from __future__ import annotations

import asyncio

import pytest
from fastmcp.exceptions import ToolError

from as_mcp_server.texts import (
    AUTO_ACCESS,
    MSG_AUTO_LIMIT,
    MSG_DUPLICATE_ENTRY,
    MSG_NOT_WRITABLE,
    NOTE_ACCESS_LIST_RESTART,
)
from as_mcp_server.tools_access_write import MSG_DEFAULT_OWNER
from tests.live.probe import T1, T2, Probe
from tests.live.test_users_groups_live import scratch  # noqa: F401  (the fixture)
from tests.live.test_writes_live import sacli
from tests.live.vpn_clients import require_client_image

WAIT_AFTER_RESTART = 75
NETWORK = {"subnet": "10.77.0.0/24", "allow": True}
HOST_T1 = {"subnet": T1, "allow": False}


async def every_list(scratch) -> list[dict]:  # noqa: F811
    return (await scratch.call("list_access_lists"))["profiles"]


async def labels(scratch, owner: str, kind: str) -> list[str]:  # noqa: F811
    key = "usernames" if kind == "user" else "group_names"
    found = await scratch.call("list_access_lists", {key: [owner]})
    return [
        f"{'allow' if p['access_route']['accept'] else 'deny'} "
        f"{p['access_route']['type']}"
        + (
            f" {p['access_route']['subnet']['netip']}"
            f"/{p['access_route']['subnet']['prefix_length']}"
            if "subnet" in p["access_route"]
            else ""
        )
        for p in found["profiles"]
        if p["type"] == "access_to_ipv4"
    ]


async def restart_and_connect(scratch, profile) -> Probe:  # noqa: F811
    """A warm restart applies the list; a client connected after it gets it."""
    for client in scratch.clients:
        client.stop()
    restarted = await scratch.call("warm_restart")
    assert restarted["items"][0]["outcome"] == "done", restarted
    await asyncio.sleep(WAIT_AFTER_RESTART)
    client = await scratch.connect(scratch.user, profile)
    return Probe(client.name)


@pytest.mark.slow
async def test_a_deny_for_one_host_in_front_of_an_allow_blocks_only_that_host(
    scratch,  # noqa: F811
) -> None:
    require_client_image()
    name = scratch.user
    before = await every_list(scratch)
    await scratch.call("create_user", {"users": [{"username": name}]})
    await scratch.call("update_user", {"usernames": [name], "autologin": True})
    profile = await scratch.autologin_profile(name)

    allowed = await scratch.call(
        "modify_access_list", {"owner": name, "add": [NETWORK]}
    )
    (item,) = allowed["items"]
    assert item["outcome"] == "done", item
    assert item["before"] == {"kind": "user", "access_list": [], "default_via": "nat"}
    assert item["after"]["access_list"] == ["allow 10.77.0.0/24 (nat)"]
    assert NOTE_ACCESS_LIST_RESTART in allowed["notes"]

    seen: list[str] = []
    denied = await scratch.call(
        "modify_access_list", {"owner": name, "add": [HOST_T1]}, seen=seen
    )
    (item,) = denied["items"]
    assert item["outcome"] == "done", item
    assert item["after"]["access_list"] == [
        "deny 10.77.0.10/32 (nat)",
        "allow 10.77.0.0/24 (nat)",
    ]
    lines = seen[0].splitlines()
    order = lines.index("    order after the change:")
    assert lines[order + 1 : order + 3] == [
        "      1. deny 10.77.0.10/32 (nat)",
        "      2. allow 10.77.0.0/24 (nat)",
    ]
    assert await labels(scratch, name, "user") == [
        "deny nat 10.77.0.10/32",
        "allow nat 10.77.0.0/24",
    ]

    probe = await restart_and_connect(scratch, profile)
    assert not probe.ping(T1)
    assert not probe.http(T1, 8080)
    assert probe.ping(T2)
    assert probe.http(T2, 8080)

    removed = await scratch.call(
        "modify_access_list", {"owner": name, "remove": [HOST_T1, NETWORK]}
    )
    (item,) = removed["items"]
    assert item["outcome"] == "done", item
    assert item["after"]["access_list"] == []
    assert await every_list(scratch) == before

    probe = await restart_and_connect(scratch, profile)
    assert not probe.ping(T1)
    assert not probe.ping(T2)
    assert not probe.http(T2, 8080)

    audit = [(line["tool"], line["outcome"]) for line in scratch.live.audit()]
    assert audit.count(("modify_access_list", "applied")) == 3
    assert audit.count(("warm_restart", "applied")) == 2


async def test_a_group_list_keeps_services_and_refuses_what_it_cannot_write(
    scratch,  # noqa: F811
) -> None:
    group = scratch.group
    before = await every_list(scratch)
    await scratch.call("create_group", {"name": group})
    entry = {
        **NETWORK,
        "via": "route",
        "services": [
            {"protocol": "tcp", "port": 8080, "end_port": 8081},
            {"protocol": "icmp", "icmp_type": "icmp-echo-request"},
        ],
    }
    label = "allow 10.77.0.0/24 tcp/8080-8081, icmp-echo-request (route)"

    added = await scratch.call("modify_access_list", {"owner": group, "add": [entry]})
    (item,) = added["items"]
    assert item["outcome"] == "done", item
    assert item["after"]["kind"] == "group"
    assert item["after"]["access_list"] == [label]

    with pytest.raises(ToolError) as error:
        await scratch.call("modify_access_list", {"owner": group, "add": [entry]})
    assert str(error.value) == MSG_DUPLICATE_ENTRY.format(owner=group, entry=label)
    with pytest.raises(ToolError) as error:
        await scratch.auto("modify_access_list", {"owner": group, "add": [HOST_T1]})
    assert str(error.value) == MSG_AUTO_LIMIT.format(reason=AUTO_ACCESS)
    with pytest.raises(ToolError) as error:
        await scratch.call(
            "modify_access_list", {"owner": "__DEFAULT__", "add": [NETWORK]}
        )
    assert str(error.value) == MSG_DEFAULT_OWNER
    with pytest.raises(ToolError) as error:
        await scratch.call(
            "modify_access_list", {"owner": f"{group}-x", "add": [NETWORK]}
        )
    assert "There is no user or group named" in str(error.value)

    # The Web API cannot write class `all`; sacli can. A deny in front of the
    # network would rewrite it, so the change is refused and nothing is written.
    sacli(
        scratch.live.name,
        "--user",
        group,
        "--key",
        "access_to.1",
        "--value",
        "+ALL",
        "UserPropPut",
    )
    assert await labels(scratch, group, "group") == [
        "allow route 10.77.0.0/24",
        "allow all",
    ]
    with pytest.raises(ToolError) as error:
        await scratch.call(
            "modify_access_list",
            {"owner": group, "add": [{**HOST_T1, "via": "route"}]},
        )
    assert str(error.value) == MSG_NOT_WRITABLE.format(owner=group, entry="allow all")
    assert await labels(scratch, group, "group") == [
        "allow route 10.77.0.0/24",
        "allow all",
    ]

    # Removing the network leaves `all` where it is: it is not rewritten.
    removed = await scratch.call(
        "modify_access_list", {"owner": group, "remove": [entry]}
    )
    (item,) = removed["items"]
    assert item["outcome"] == "done", item
    assert item["after"]["access_list"] == ["allow all"]

    sacli(scratch.live.name, "--user", group, "UserPropDelAll")
    assert await every_list(scratch) == before
