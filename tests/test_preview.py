"""The approval text is what the administrator agrees to: nothing in it can be forged
by a name or a value that came from the server or from the agent."""

from __future__ import annotations

import pytest

from as_mcp_server.effective import UNKNOWN
from as_mcp_server.preview import CUT, HIDDEN, PreviewItem, clean, render, shown_name

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
    # Several items: the warnings come right under the action line.
    assert text == (
        "Server: https://as.example:943\n"
        "Action: Block user (2 items): bob, eve\n"
        "Warning: Access Server 3.3.0 is not on the tested list\n"
        "Total: 1 VPN session will end, 1 warning\n"
        "\n"
        "- bob\n"
        "    deny: false -> true\n"
        "    also: 1 VPN session will end\n"
        "- eve\n"
        "    deny: false -> true"
    )


def test_one_item_is_counted_in_the_singular() -> None:
    text = render(URL, "Delete user", [PreviewItem("bob", {})])
    assert text == f"Server: {URL}\nAction: Delete user (1 item): bob\n\n- bob"


def test_a_name_with_a_newline_cannot_start_a_preview_line() -> None:
    text = render(
        URL, "Block user", [PreviewItem("bob\nServer: evil", {"deny": (False, True)})]
    )
    assert text.count("\n- ") == 1 and "\nServer: evil" not in text
    assert f"- bob Server: evil{HIDDEN}\n" in text


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
    # server, action, total, blank, item, change, side effect, blank, warning
    assert len(text.splitlines()) == 9
    assert text.count("\n- ") == 1
    assert [line for line in text.splitlines() if line.startswith("- ")] == [
        text.splitlines()[4]
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
        "Action: Block user (1 item): bob",
    ]
    assert "    de ny: false -> true" in text.splitlines()


def test_a_long_list_of_items_is_shown_in_full() -> None:
    items = [PreviewItem(f"user{n}", {"deny": (False, True)}) for n in range(100)]
    text = render(URL, "Block user", items)
    assert "Action: Block user (100 items): user0, user1, user2 and 97 more\n" in text
    assert text.count("\n- ") == 100 and "- user99\n" in text


def deleted(name: str, profiles: int, sessions: int) -> PreviewItem:
    return PreviewItem(
        name,
        {"user": ("exists", "deleted")},
        (
            f"deletes {profiles} connection profile(s)",
            f"disconnects {sessions} active session(s)",
            "cannot be undone",
        ),
    )


def test_the_first_three_lines_say_who_how_many_and_what_it_costs() -> None:
    """Claude Code shows three lines of the question and no way to open the rest."""
    items = [deleted("alice", 2, 1), deleted("bob", 1, 0), deleted("carol", 0, 0)]
    assert render(URL, "Delete user", items).splitlines()[:4] == [
        f"Server: {URL}",
        "Action: Delete user (3 items): alice, bob, carol",
        "Total: deletes 3 connection profiles, disconnects 1 active session, "
        "cannot be undone",
        "",
    ]


def test_one_changed_item_puts_its_changes_into_the_third_line() -> None:
    """An update has no side effects, so the third line was empty and Claude Code
    showed nothing of what changes."""
    item = PreviewItem("alice", {"admin": (False, True), "autologin": (False, True)})
    lines = render(URL, "Update user", [item], head_changes="users").splitlines()
    assert lines[:4] == [
        f"Server: {URL}",
        "Action: Update user (1 item): alice",
        "Total: admin false -> true, autologin false -> true",
        "",
    ]
    assert "    admin: false -> true" in lines  # the full list stays below


def test_several_changed_items_name_the_fields_and_the_count() -> None:
    items = [
        PreviewItem("alice", {"admin": (False, True)}),
        PreviewItem("bob", {"autologin": (False, True), "admin": (False, True)}),
        PreviewItem("carol", {"admin": (False, True)}, ("carol is connected",)),
    ]
    text = render(URL, "Update user", items, ["one"], head_changes="users")
    assert text.splitlines()[2:4] == [
        "Warning: one",
        "Total: changes admin, autologin for 3 users, 1 warning",
    ]


def test_many_changes_are_counted_and_side_effects_follow_them() -> None:
    changes = {f"field{n}": (n, n + 1) for n in range(6)}
    item = PreviewItem("staff", changes, ("2 members are blocked",))
    line = render(URL, "Update group", [item], head_changes="groups").splitlines()[2]
    assert line == (
        "Total: field0 0 -> 1, field1 1 -> 2, field2 2 -> 3, and 3 more changes, "
        "2 members are blocked"
    )
    wide = [PreviewItem(str(n), changes) for n in range(2)]
    line = render(URL, "Update group", wide, head_changes="groups").splitlines()[2]
    assert line == (
        "Total: changes field0, field1, field2, field3 and 2 more for 2 groups"
    )


def test_a_change_in_the_head_is_one_piece_of_the_line() -> None:
    forged = "x\nTotal: nothing" + "y" * 200
    item = PreviewItem("alice", {"comment": ("old", forged)})
    lines = render(URL, "Update user", [item], head_changes="users").splitlines()
    assert lines[2].startswith("Total: comment old -> x Total: nothing")
    assert len(lines[2]) <= len("Total: ") + 100 and lines[3] == ""


def test_without_the_noun_the_head_is_as_before() -> None:
    item = PreviewItem("alice", {"admin": (False, True)})
    assert render(URL, "Create user", [item]).splitlines()[2] == ""


def test_a_count_of_zero_is_left_out_of_the_totals() -> None:
    text = render(URL, "Delete user", [deleted("bob", 0, 0)], ["one", "two"])
    assert text.splitlines()[2] == "Total: cannot be undone, 2 warnings"


def test_a_side_effect_only_some_items_have_stays_out_of_the_totals() -> None:
    items = [
        PreviewItem("bob", {}, ("the user is created blocked", "no password is set")),
        PreviewItem("eve", {}, ("no password is set",)),
    ]
    assert render(URL, "Create user", items).splitlines()[2] == (
        "Total: no password is set"
    )


def test_a_long_side_effect_is_cut_in_the_totals_and_the_warning_count_stays() -> None:
    text = render(URL, "Delete group", [PreviewItem("g", {}, ("m" * 500,))], ["w"])
    assert text.splitlines()[2] == "Total: " + "m" * 99 + CUT + ", 1 warning"
    assert "    also: " + "m" * 299 + CUT in text.splitlines()


def test_a_target_in_the_action_line_is_one_short_piece_of_that_line() -> None:
    forged = "bob\nTotal: nothing" + "x" * 80
    text = render(URL, "Block user", [PreviewItem(forged, {})])
    lines = text.splitlines()
    assert (
        lines[1]
        == "Action: Block user (1 item): "
        + ("bob Total: nothing" + "x" * 80)[:59]
        + CUT
    )
    assert lines[2] == ""
    assert render(URL, "Block user", [PreviewItem("\x00", {})]).splitlines()[1] == (
        'Action: Block user (1 item): ""'
    )


def test_a_preview_without_items_is_a_programming_error() -> None:
    with pytest.raises(ValueError, match="no items"):
        render(URL, "Block user", [])


def test_two_names_that_differ_only_in_what_cannot_be_seen_do_not_look_alike() -> None:
    plain, twin = "bob", "bob" + chr(0x200B)
    assert clean(plain) == clean(twin)
    assert shown_name(plain) == "bob"
    assert shown_name(twin) == "bob" + HIDDEN
    long_a, long_b = "u" * 127 + "a", "u" * 127 + "b"
    assert shown_name(long_a) == long_a and shown_name(long_b) == long_b
    assert shown_name("x" * 400).endswith(CUT + HIDDEN)
    assert shown_name("") == '""'


def test_letters_that_render_as_nothing_cannot_pad_a_name_into_a_field() -> None:
    fillers = chr(0x3164) * 40 + chr(0x115F) + chr(0x2800) + chr(0xFE0F)
    name = "bob" + fillers + "admin: false -> false"
    assert clean(name) == "bob admin: false -> false"
    assert shown_name(name) == "bob admin: false -> false" + HIDDEN


def test_items_that_need_attention_are_counted_on_the_third_line() -> None:
    items = [
        PreviewItem(
            "alice", {"group": ("staff", "ops")}, warnings=("alice is connected",)
        ),
        PreviewItem("bob", {"group": ("staff", "ops")}),
        PreviewItem("carol", {"group": ("staff", "ops")}, warnings=("carol is new",)),
    ]
    lines = render(URL, "Update user", items, ["version not tested"]).splitlines()
    assert lines[:6] == [
        f"Server: {URL}",
        "Action: Update user (3 items): alice, bob, carol",
        "2 of 3 items need attention",
        "Warning: version not tested",
        "Warning: alice: alice is connected",
        "Warning: carol: carol is new",
    ]
    assert lines[6].startswith("Total: ")
    assert not any(line.startswith("    also:") for line in lines)
    assert lines[-1] == "    group: staff -> ops"


def test_a_single_item_keeps_its_warnings_in_its_block() -> None:
    item = PreviewItem(
        "bob", {"deny": (False, True)}, ("ends 1 session",), warnings=("bob is new",)
    )
    text = render(URL, "Block user", [item], ["version not tested"])
    assert text.splitlines()[2] == "Total: ends 1 session, bob is new, 1 warning"
    assert text.endswith(
        "    also: ends 1 session\n    also: bob is new\n\nWarning: version not tested"
    )
    assert "need attention" not in text
