"""The probe network of the dev stand: two hosts that a VPN user reaches only through
an access rule. The access tools of 0.3.0 check their traffic with it."""

from __future__ import annotations

import subprocess

from tests.live.probe import NAME_T1, NAME_T2, T1, T2, Probe
from tests.live.test_users_groups_live import scratch  # noqa: F401  (the fixture)


async def connected_probe(scratch) -> Probe:  # noqa: F811
    name = scratch.user
    await scratch.call("create_user", {"users": [{"username": name}]})
    await scratch.call("update_user", {"usernames": [name], "autologin": True})
    client = await scratch.connect(name, await scratch.autologin_profile(name))
    return Probe(client.name)


def test_the_server_reaches_both_probe_hosts(stand) -> None:
    name, _ = stand
    for ip in (T1, T2):
        done = subprocess.run(
            [
                "docker",
                "exec",
                name,
                "curl",
                "-s",
                "-o",
                "/dev/null",
                "-m",
                "3",
                "-w",
                "%{http_code}",
                f"http://{ip}:8080/",
            ],
            capture_output=True,
            text=True,
        )
        assert done.stdout == "200", f"{name} cannot reach {ip}; run make stand-up"


async def test_without_a_rule_a_vpn_user_reaches_no_probe_host(scratch) -> None:  # noqa: F811
    probe = await connected_probe(scratch)
    assert not probe.ping(T1)
    assert not probe.http(T1, 8080)
    assert not probe.ping(T2)


async def test_the_vpn_dns_answers_the_probe_names(scratch) -> None:  # noqa: F811
    probe = await connected_probe(scratch)
    assert probe.lookup(NAME_T1) == [T1]
    assert probe.lookup(NAME_T2) == [T2]
