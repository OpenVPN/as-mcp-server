"""Which Access Server versions may be written to, and with which warning."""

from __future__ import annotations

import pytest

from as_mcp_server.versions import (
    below_minimum_version,
    parse_minor,
    untested_refusal,
    untested_warning,
    version_status,
)


@pytest.mark.parametrize(
    ("version", "status"),
    [
        ("3.1.0", "tested"),
        ("3.2.4", "tested"),
        ("3.3.0", "untested"),
        ("4.0", "untested"),
        ("3.0.2", "unsupported"),
        ("", "unsupported"),
        ("beta", "unsupported"),
    ],
)
def test_a_version_is_tested_untested_or_unsupported(version: str, status: str) -> None:
    assert version_status(version) == status


def test_an_unreadable_version_counts_as_below_the_minimum() -> None:
    assert below_minimum_version("beta") is True
    assert below_minimum_version("") is True
    assert below_minimum_version("3.0.2") is True
    assert below_minimum_version("3.1.0") is False


def test_only_the_first_two_numbers_of_a_version_are_read() -> None:
    assert parse_minor("3.2.4") == (3, 2)
    assert parse_minor("3.2.4-f3c295a7") == (3, 2)
    assert parse_minor("3") is None


def test_the_untested_warning_names_both_minor_versions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("as_mcp_server.versions.__version__", "0.2.0")
    assert untested_warning("3.3.1") == (
        "Access Server 3.3 is not on the tested list of as-mcp-server 0.2"
    )


def test_the_untested_refusal_names_both_minor_versions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("as_mcp_server.versions.__version__", "0.3.0")
    assert untested_refusal("3.3.1") == (
        "Refused: Access Server 3.3 is not on the tested list of as-mcp-server 0.3, "
        "and access lists are changed only on tested versions. Make the change in "
        "the Admin UI."
    )
