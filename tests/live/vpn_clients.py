"""Real OpenVPN clients for the live tests: one container per client, on the
network of the dev stand.

OPENVPN_AS_LIVE_VPN_CLIENT picks the client: "3" (the default) is OpenVPN 3 Linux
(dev/vpn-client3), "2" is OpenVPN 2.6 (dev/vpn-client). The two reconnect differently,
so a full check runs the live tests once with each."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from tests.live.conftest import ROOT

NETWORK = "dev_default"
KIND = os.environ.get("OPENVPN_AS_LIVE_VPN_CLIENT", "3")
if KIND == "2":
    IMAGE, SOURCE = "as-mcp-dev/vpn-client:1", "vpn-client"
    CONNECTED = "Initialization Sequence Completed"
    REFUSED = "AUTH_FAILED"
    RUN = ("--cap-add", "NET_ADMIN", "--device", "/dev/net/tun")
elif KIND == "3":
    IMAGE, SOURCE = "as-mcp-dev/vpn-client3:1", "vpn-client3"
    CONNECTED = "Client INFO: Connected:"
    REFUSED = "User authentication failed"
    RUN = ("--privileged",)
else:
    raise RuntimeError("OPENVPN_AS_LIVE_VPN_CLIENT must be 2 or 3")


def docker(*args: str, check: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args], check=check, text=True, capture_output=True
    )


def require_client_image() -> None:
    if shutil.which("docker") is None:
        pytest.skip("docker is needed to run a VPN client")
    if not docker("image", "inspect", IMAGE).stdout.strip().startswith("["):
        docker("build", "-q", "-t", IMAGE, str(ROOT / "dev" / SOURCE), check=True)


def address_of(stand: str) -> str:
    template = "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"
    return docker("inspect", "-f", template, stand, check=True).stdout.strip()


def for_the_stand(profile: Path, stand: str, directory: Path) -> Path:
    """A copy of the profile whose `remote` lines point at the stand container: the
    profile carries the server's host.name, which the containers do not resolve."""
    text = profile.read_text("utf-8")
    text = re.sub(
        r"^(remote )\S+( .*)$", rf"\g<1>{address_of(stand)}\g<2>", text, flags=re.M
    )
    copy = directory / f"stand-{profile.name}"
    copy.write_text(text, "utf-8")
    copy.chmod(0o600)
    return copy


class VpnClient:
    def __init__(self, name: str, profile: Path, auth: Path | None = None) -> None:
        """`auth` is a file with the username and the password on two lines, for a
        profile that asks for them (userlogin)."""
        self.name = name
        self.profile = profile
        self.auth = auth

    def start(self) -> VpnClient:
        self.stop()
        mounts = ["-v", f"{self.profile}:/client.ovpn:ro"]
        options: list[str] = []
        if self.auth is not None:
            mounts += ["-v", f"{self.auth}:/auth.txt:ro"]
            if KIND == "2":
                options = ["--auth-user-pass", "/auth.txt", "--auth-retry", "none"]
        docker(
            *("run", "-d", "--name", self.name, "--network", NETWORK),
            *RUN,
            *mounts,
            IMAGE,
            *options,
            check=True,
        )
        return self

    def log(self) -> str:
        result = docker("logs", self.name)
        return result.stdout + result.stderr

    def running(self) -> bool:
        state = docker("inspect", "-f", "{{.State.Running}}", self.name)
        return state.stdout.strip() == "true"

    def wait_connected(self, seconds: float = 30) -> bool:
        return self._wait(lambda: CONNECTED in self.log(), seconds, stop_when_dead=True)

    def wait_exited(self, seconds: float = 20) -> bool:
        return self._wait(lambda: not self.running(), seconds)

    def refused(self, reason: str = "") -> bool:
        """Whether the server turned the client away. OpenVPN 2 prints the server's
        reason (`AUTH_FAILED,DENY`); OpenVPN 3 prints only that authentication
        failed, so `reason` is checked for OpenVPN 2 alone."""
        wanted = f"{REFUSED},{reason}" if reason and KIND == "2" else REFUSED
        return wanted in self.log()

    def _wait(self, done, seconds: float, *, stop_when_dead: bool = False) -> bool:
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if done():
                return True
            if stop_when_dead and not self.running():
                return done()
            time.sleep(0.5)
        return done()

    def stop(self) -> None:
        """SIGTERM first: the client then tells the server it leaves. A killed
        client stays in /vpn/status for a long time and counts against the two
        connections the stand allows."""
        docker("stop", "-t", "5", self.name)
        docker("rm", "-f", self.name)
