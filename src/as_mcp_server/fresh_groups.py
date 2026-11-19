"""Groups created through this server that still wait for a restart.

Access Server refuses the VPN connections of the members of a group until its next
restart, and cannot say which groups those are. So `create_group` writes the name
down here, next to the restart time the server showed then. A name counts as long
as the server still shows that same restart time, which also covers a restart made
somewhere else. The list is a file, so it is still there in the next session.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

FILE_NAME = "fresh_groups.json"


class FreshGroups:
    def __init__(self, config_dir: Path) -> None:
        self.path = Path(config_dir) / FILE_NAME

    def add(self, server_url: str, restarted: Any, name: str) -> None:
        servers = self._load()
        entry = servers.get(server_url)
        if entry is None or entry["restarted"] != restarted:
            entry = {"restarted": restarted, "groups": []}
        if name.casefold() not in entry["groups"]:
            entry["groups"].append(name.casefold())
        self._save({**servers, server_url: entry})

    def remove(self, server_url: str, name: str) -> None:
        servers = self._load()
        entry = servers.get(server_url)
        if entry is None or name.casefold() not in entry["groups"]:
            return
        entry["groups"].remove(name.casefold())
        self._save(servers)

    def has(self, server_url: str, restarted: Any, name: str) -> bool:
        """Was `name` created since the restart the server shows as `restarted`?"""
        entry = self._load().get(server_url)
        return (
            entry is not None
            and entry["restarted"] == restarted
            and name.casefold() in entry["groups"]
        )

    def _load(self) -> dict[str, dict[str, Any]]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            log.warning("Cannot read %s: %s", self.path, exc)
            return {}
        servers = data.get("servers") if isinstance(data, dict) else None
        if not isinstance(servers, dict):
            return {}
        return {
            str(url): {"restarted": entry["restarted"], "groups": list(entry["groups"])}
            for url, entry in servers.items()
            if isinstance(entry, dict)
            and "restarted" in entry
            and isinstance(entry.get("groups"), list)
        }

    def _save(self, servers: dict[str, dict[str, Any]]) -> None:
        kept = {url: entry for url, entry in servers.items() if entry["groups"]}
        text = json.dumps({"version": 1, "servers": kept}, indent=2, sort_keys=True)
        temporary = self.path.with_name(f"{FILE_NAME}.tmp")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            descriptor = os.open(temporary, flags, 0o600)
            try:
                os.write(descriptor, f"{text}\n".encode())
            finally:
                os.close(descriptor)
            os.replace(temporary, self.path)
        except OSError as exc:
            log.warning("Cannot write %s: %s", self.path, exc)
