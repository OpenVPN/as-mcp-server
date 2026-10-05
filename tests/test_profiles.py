"""profiles.toml holds URL and username per profile.

It is written by hand and read by tomllib.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from as_mcp_server.profiles import (
    Profile,
    ProfilesError,
    delete_profile,
    profiles_path,
    read_profiles,
    write_profile,
)


def test_a_missing_file_means_no_profiles(tmp_path: Path) -> None:
    assert read_profiles(tmp_path / "nowhere") == {}


def test_write_then_read_round_trips_including_quotes_and_unicode(
    tmp_path: Path,
) -> None:
    profile = Profile(url="https://vpn.example.com:943", username='ops "admin" Ünïcode')
    path = write_profile(tmp_path, "default", profile)
    assert path == profiles_path(tmp_path) == tmp_path / "profiles.toml"
    assert read_profiles(tmp_path) == {"default": profile}
    text = path.read_text(encoding="utf-8")
    assert text.startswith("[default]\n")
    assert 'url = "https://vpn.example.com:943"' in text


def test_writing_a_second_profile_keeps_the_first(tmp_path: Path) -> None:
    write_profile(tmp_path, "default", Profile("https://a.example:943", "a"))
    write_profile(tmp_path, "prod", Profile("https://b.example:943", "b"))
    assert set(read_profiles(tmp_path)) == {"default", "prod"}
    assert read_profiles(tmp_path)["default"].username == "a"


def test_delete_reports_whether_something_was_removed(tmp_path: Path) -> None:
    write_profile(tmp_path, "default", Profile("https://a.example:943", "a"))
    assert delete_profile(tmp_path, "default") is True
    assert delete_profile(tmp_path, "default") is False
    assert read_profiles(tmp_path) == {}


@pytest.mark.skipif(os.name != "posix", reason="file modes are POSIX-only")
def test_the_file_is_private_to_the_user(tmp_path: Path) -> None:
    path = write_profile(tmp_path, "default", Profile("https://a.example:943", "a"))
    assert oct(path.stat().st_mode & 0o777) == "0o600"


def test_a_profile_name_with_spaces_or_dots_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ProfilesError, match="invalid"):
        write_profile(tmp_path, "my prod", Profile("https://a.example:943", "a"))
    with pytest.raises(ProfilesError, match="invalid"):
        write_profile(tmp_path, "a.b", Profile("https://a.example:943", "a"))


def test_a_malformed_file_is_reported_with_its_path(tmp_path: Path) -> None:
    (tmp_path / "profiles.toml").write_text("[default\nurl = 1\n", encoding="utf-8")
    with pytest.raises(ProfilesError, match=r"profiles\.toml"):
        read_profiles(tmp_path)


def test_a_section_without_url_and_username_is_reported(tmp_path: Path) -> None:
    (tmp_path / "profiles.toml").write_text("[default]\nurl = 42\n", encoding="utf-8")
    with pytest.raises(ProfilesError, match="url"):
        read_profiles(tmp_path)
