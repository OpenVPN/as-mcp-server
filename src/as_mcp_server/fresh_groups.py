"""Groups created through this server that still wait for a restart.

Access Server refuses the VPN connections of the members of a group until its next
restart, and cannot say which groups those are. So `create_group` writes the name
down here, next to the restart time the server showed then. A name counts as long
as the server still shows that same restart time, which also covers a restart made
somewhere else. The list is a file, so it is still there in the next session.

A name the server had at its last restart keeps working when the group is deleted
and created again (measured on 3.1.0 and 3.2.4). So `delete_group` writes such a
name down as known, and `create_group` does not count it as new.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

FILE_NAME = "fresh_groups.json"


def _names(value: Any) -> list[str]:
    return (
        [name for name in value if isinstance(name, str)]
        if isinstance(value, list)
        else []
    )


class FreshGroups:
    def __init__(self, config_dir: Path) -> None:
        self.path = Path(config_dir) / FILE_NAME

    def add(self, server_url: str, restarted: Any, name: str) -> None:
        """A group was created. Nothing is noted for a name the server knows."""
        servers = self._load()
        entry = self._entry(servers, server_url, restarted)
        key = name.casefold()
        if key in entry["known"] or key in entry["groups"]:
            return
        entry["groups"].append(key)
        self._save(servers)

    def remove(self, server_url: str, restarted: Any, name: str) -> None:
        """A group was deleted. One that did not wait for a restart was there at
        the last one, so the server still knows its name."""
        servers = self._load()
        entry = self._entry(servers, server_url, restarted)
        key = name.casefold()
        if key in entry["groups"]:
            entry["groups"].remove(key)
        elif key not in entry["known"]:
            entry["known"].append(key)
        self._save(servers)

    def has(self, server_url: str, restarted: Any, name: str) -> bool:
        """Was `name` created since the restart the server shows as `restarted`?"""
        return self._listed(server_url, restarted, name, "groups")

    def knows(self, server_url: str, restarted: Any, name: str) -> bool:
        """Did the server have `name` at the restart it shows as `restarted`, as
        far as the groups deleted through this server tell?"""
        return self._listed(server_url, restarted, name, "known")

    def _listed(self, server_url: str, restarted: Any, name: str, where: str) -> bool:
        entry = self._load().get(server_url)
        return (
            entry is not None
            and entry["restarted"] == restarted
            and name.casefold() in entry[where]
        )

    @staticmethod
    def _entry(
        servers: dict[str, dict[str, Any]], server_url: str, restarted: Any
    ) -> dict[str, Any]:
        """The entry of this server for this restart; an older one is dropped."""
        entry = servers.get(server_url)
        if entry is None or entry["restarted"] != restarted:
            entry = {"restarted": restarted, "groups": [], "known": []}
            servers[server_url] = entry
        return entry

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
            str(url): {
                "restarted": entry["restarted"],
                "groups": _names(entry.get("groups")),
                "known": _names(entry.get("known")),
            }
            for url, entry in servers.items()
            if isinstance(entry, dict) and "restarted" in entry
        }

    def _save(self, servers: dict[str, dict[str, Any]]) -> None:
        kept = {
            url: entry
            for url, entry in servers.items()
            if entry["groups"] or entry["known"]
        }
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
