"""Real OpenVPN clients for the live tests: one container per client, on the
network of the dev stand (dev/vpn-client/Dockerfile)."""

from __future__ import annotations

import re
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from tests.live.conftest import ROOT

IMAGE = "as-mcp-dev/vpn-client:1"
NETWORK = "dev_default"
CONNECTED = "Initialization Sequence Completed"


def docker(*args: str, check: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args], check=check, text=True, capture_output=True
    )


def require_client_image() -> None:
    if shutil.which("docker") is None:
        pytest.skip("docker is needed to run a VPN client")
    if not docker("image", "inspect", IMAGE).stdout.strip().startswith("["):
        docker("build", "-q", "-t", IMAGE, str(ROOT / "dev" / "vpn-client"), check=True)


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
            options = ["--auth-user-pass", "/auth.txt", "--auth-retry", "none"]
        docker(
            *("run", "-d", "--name", self.name, "--network", NETWORK),
            *("--cap-add", "NET_ADMIN", "--device", "/dev/net/tun"),
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
