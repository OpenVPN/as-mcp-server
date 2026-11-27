"""Traffic checks from inside a VPN client container.

The checks run in a sidecar that shares the client's network namespace, so they go
through the tunnel. The sidecar is the OpenVPN 2 image (Alpine, busybox ping, wget and
nslookup); the OpenVPN 3 image has no ping. The hosts come from dev/compose.yaml."""

from __future__ import annotations

import re

from tests.live.conftest import ROOT
from tests.live.vpn_clients import docker

T1, T2 = "10.77.0.10", "10.77.0.11"
NAME_T1, NAME_T2 = "t1.mcpprobe.test", "t2.mcpprobe.test"
VPN_DNS = "172.27.224.1"
SIDECAR = "as-mcp-dev/vpn-client:1"


class Probe:
    def __init__(self, client: str) -> None:
        self.client = client
        if docker("image", "inspect", SIDECAR).returncode != 0:
            docker(
                "build",
                "-q",
                "-t",
                SIDECAR,
                str(ROOT / "dev" / "vpn-client"),
                check=True,
            )

    def _run(self, script: str):
        return docker(
            "run",
            "--rm",
            "--network",
            f"container:{self.client}",
            "--entrypoint",
            "sh",
            SIDECAR,
            "-c",
            script,
        )

    def ping(self, ip: str) -> bool:
        return self._run(f"ping -c 2 -W 2 {ip}").returncode == 0

    def http(self, ip: str, port: int) -> bool:
        return (
            self._run(f"wget -q -T 3 -O /dev/null http://{ip}:{port}/").returncode == 0
        )

    def lookup(self, name: str, dns: str = VPN_DNS) -> list[str] | str:
        """The addresses of the answer, or the line that says why there is none
        (for example `** server can't find ...: REFUSED`)."""
        text = self._run(f"timeout 6 nslookup {name} {dns} 2>&1").stdout
        answer = text.split("Name:", 1)[1] if "Name:" in text else ""
        found = re.findall(r"^Address\S*:\s*(\d+\.\d+\.\d+\.\d+)$", answer, re.M)
        if found:
            return found
        reasons = [line for line in text.splitlines() if "can't find" in line]
        return reasons[0] if reasons else text.strip()[-200:]
