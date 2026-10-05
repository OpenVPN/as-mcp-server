"""The profiles file: URL and username per profile, never the password.

TOML so an administrator can read and edit it by hand. Writing uses a tiny hand-rolled
serializer because the standard library reads TOML (tomllib) but does not write it, and
the file only ever holds string values. `json.dumps` produces a double-quoted string
whose escapes are all valid TOML basic-string escapes.
"""

from __future__ import annotations

import json
import os
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

PROFILES_FILENAME = "profiles.toml"
_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class ProfilesError(Exception):
    """The profiles file cannot be read, or a profile name is invalid."""


@dataclass(frozen=True)
class Profile:
    url: str
    username: str


def profiles_path(config_dir: Path) -> Path:
    return config_dir / PROFILES_FILENAME


def validate_name(name: str) -> str:
    if not _NAME_RE.match(name):
        raise ProfilesError(
            f"Profile name {name!r} is invalid: use letters, digits, '-' and '_' only."
        )
    return name


def read_profiles(config_dir: Path) -> dict[str, Profile]:
    path = profiles_path(config_dir)
    if not path.exists():
        return {}
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ProfilesError(f"Cannot read {path}: {exc}") from exc
    profiles: dict[str, Profile] = {}
    for name, section in data.items():
        if not isinstance(section, dict):
            raise ProfilesError(
                f"{path}: [{name}] must be a table with url and username."
            )
        url, username = section.get("url"), section.get("username")
        if not isinstance(url, str) or not isinstance(username, str):
            raise ProfilesError(
                f"{path}: [{name}] needs the string keys 'url' and 'username'."
            )
        profiles[name] = Profile(url=url, username=username)
    return profiles


def write_profile(config_dir: Path, name: str, profile: Profile) -> Path:
    validate_name(name)
    profiles = read_profiles(config_dir)
    profiles[name] = profile
    return _write_all(config_dir, profiles)


def delete_profile(config_dir: Path, name: str) -> bool:
    profiles = read_profiles(config_dir)
    if name not in profiles:
        return False
    del profiles[name]
    _write_all(config_dir, profiles)
    return True


def _write_all(config_dir: Path, profiles: dict[str, Profile]) -> Path:
    path = profiles_path(config_dir)
    config_dir.mkdir(parents=True, exist_ok=True)
    text = "".join(
        f"[{name}]\nurl = {json.dumps(p.url)}\nusername = {json.dumps(p.username)}\n\n"
        for name, p in profiles.items()
    )
    path.write_text(text, encoding="utf-8")
    if os.name == "posix":
        os.chmod(path, 0o600)
    return path
