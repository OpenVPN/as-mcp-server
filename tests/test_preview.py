"""The approval text is what the administrator agrees to: nothing in it can be forged
by a name or a value that came from the server or from the agent."""

from __future__ import annotations

import pytest

from as_mcp_server.effective import UNKNOWN
from as_mcp_server.preview import PreviewItem, clean, render

URL = "https://as.example:943"


def test_the_text_names_the_server_the_action_and_every_item() -> None:
    text = render(
        URL,
        "Block user",
        [
            PreviewItem("bob", {"deny": (False, True)}, ("1 VPN session will end",)),
            PreviewItem("eve", {"deny": (False, True)}),
        ],
        ["Access Server 3.3.0 is not on the tested list"],
    )
    assert text == (
        "Server: https://as.example:943\n"
        "Action: Block user (2 items)\n"
        "\n"
        "- bob\n"
        "    deny: false -> true\n"
        "    also: 1 VPN session will end\n"
        "- eve\n"
        "    deny: false -> true\n"
        "\n"
        "Warning: Access Server 3.3.0 is not on the tested list"
    )


def test_one_item_is_counted_in_the_singular() -> None:
    text = render(URL, "Delete user", [PreviewItem("bob", {})])
    assert text == f"Server: {URL}\nAction: Delete user (1 item)\n\n- bob"


def test_a_name_with_a_newline_cannot_start_a_preview_line() -> None:
    text = render(
        URL, "Block user", [PreviewItem("bob\nServer: evil", {"deny": (False, True)})]
    )
    assert text.count("\n- ") == 1 and "\nServer: evil" not in text
    assert "- bob Server: evil\n" in text


@pytest.mark.parametrize(
    "forged",
    [
        "bob\n- alice\n    admin: false -> true",
        "bob\r\n- alice",
        "bob\N{LINE SEPARATOR}- alice",
        "bob\N{PARAGRAPH SEPARATOR}- alice",
        "bob\x0b- alice",
        "bob\x0c- alice",
        "bob\x85- alice",
    ],
)
def test_no_kind_of_line_break_in_a_value_makes_a_second_item(forged: str) -> None:
    text = render(
        URL,
        "Update user",
        [PreviewItem(forged, {"comment": (forged, forged)}, (forged,))],
        [forged],
    )
    # server, action, blank, item, change, side effect, blank, warning
    assert len(text.splitlines()) == 8
    assert text.count("\n- ") == 1
    assert [line for line in text.splitlines() if line.startswith("- ")] == [
        text.splitlines()[3]
    ]


def test_control_characters_are_removed_and_long_values_are_cut_visibly() -> None:
    cleaned = clean("a\x1b[31mb\tc" + "x" * 500)
    assert cleaned == "a[31mb c" + "x" * 111 + "…"
    assert len(cleaned) == 120


def test_a_value_at_the_limit_is_not_marked_as_cut() -> None:
    assert clean("x" * 120) == "x" * 120
    assert clean("x" * 121) == "x" * 119 + "…"
    assert clean("abcdef", limit=4) == "abc…"


def test_characters_that_reorder_or_hide_text_are_removed() -> None:
    """Right-to-left overrides and zero-width characters can make `admin` read as
    something else on screen."""
    hidden = (
        "ad\N{RIGHT-TO-LEFT OVERRIDE}min\N{ZERO WIDTH SPACE}\N{ZERO WIDTH JOINER}"
        "\N{ZERO WIDTH NO-BREAK SPACE}\N{LEFT-TO-RIGHT ISOLATE}x"
        "\N{POP DIRECTIONAL ISOLATE}"
    )
    assert clean(hidden) == "adminx"


def test_spaces_collapse_and_the_ends_are_trimmed() -> None:
    assert clean("  a \t\n  b\N{NO-BREAK SPACE}\N{NO-BREAK SPACE}c  ") == "a b c"


def test_letters_of_other_alphabets_stay() -> None:
    assert clean("жанна 密钥 Zoë") == "жанна 密钥 Zoë"


@pytest.mark.parametrize(
    ("value", "shown"),
    [
        (True, "true"),
        (False, "false"),
        (None, "(not set)"),
        ("", '""'),
        ("   ", '""'),
        ("\x00\x01", '""'),
        (0, "0"),
        (42, "42"),
        ("local", "local"),
        (["a", "b"], "a, b"),
        ([], "(none)"),
        (UNKNOWN, "inherited (server-wide value unknown)"),
    ],
)
def test_values_are_shown_the_way_an_admin_reads_them(
    value: object, shown: str
) -> None:
    text = render(URL, "Update user", [PreviewItem("bob", {"field": (value, "x")})])
    assert f"    field: {shown} -> x" in text.splitlines()


def test_an_unknown_value_after_a_reset_is_said_in_words() -> None:
    text = render(URL, "Update user", [PreviewItem("bob", {"totp": (True, UNKNOWN)})])
    assert "    totp: true -> inherited (server-wide value unknown)" in text


def test_a_target_that_cleans_to_nothing_is_still_a_visible_item() -> None:
    text = render(URL, "Delete user", [PreviewItem("\x00\x1b", {})])
    assert text.splitlines()[3] == '- ""'


def test_field_names_the_server_url_and_the_action_are_cleaned_too() -> None:
    text = render(
        "https://as.example\n- forged",
        "Block\nuser",
        [PreviewItem("bob", {"de\nny": (False, True)})],
    )
    assert text.splitlines()[:2] == [
        "Server: https://as.example - forged",
        "Action: Block user (1 item)",
    ]
    assert "    de ny: false -> true" in text.splitlines()


def test_a_long_list_of_items_is_shown_in_full() -> None:
    items = [PreviewItem(f"user{n}", {"deny": (False, True)}) for n in range(100)]
    text = render(URL, "Block user", items)
    assert "Action: Block user (100 items)" in text
    assert text.count("\n- ") == 100 and "- user99\n" in text


def test_a_preview_without_items_is_a_programming_error() -> None:
    with pytest.raises(ValueError, match="no items"):
        render(URL, "Block user", [])
