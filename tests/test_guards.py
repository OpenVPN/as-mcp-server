"""Refusals decided before any write: self-lockout and the automatic-mode limits."""

from __future__ import annotations

import pytest

from as_mcp_server.effective import GUARDED, UNKNOWN
from as_mcp_server.guards import (
    Effect,
    auto_limit_reason,
    lockout_reason,
    newly_denied,
)

SAFE = {
    "deny": False,
    "deny_web": False,
    "admin": True,
    "auth_method": "local",
    "totp": False,
    "autologin": False,
    "group": None,
}
PLAIN = {**SAFE, "admin": False}


def own(**after: object) -> list[Effect]:
    return [Effect("user", "openvpn", SAFE, {**SAFE, **after})]


def test_the_own_account_is_matched_in_any_letter_case() -> None:
    effect = Effect("user", "OpenVPN", SAFE, {**SAFE, "deny": True})
    assert lockout_reason("openvpn", None, [effect])


def test_blocking_the_own_account_is_a_lockout() -> None:
    assert lockout_reason("openvpn", None, own(deny=True))


def test_blocking_the_own_web_access_is_a_lockout() -> None:
    assert lockout_reason("openvpn", None, own(deny_web=True))


def test_removing_the_own_admin_right_is_a_lockout() -> None:
    assert lockout_reason("openvpn", None, own(admin=False))


def test_changing_the_own_authentication_method_is_a_lockout() -> None:
    assert lockout_reason("openvpn", None, own(auth_method="ldap"))


def test_moving_the_own_account_to_another_group_is_a_lockout() -> None:
    assert lockout_reason("openvpn", None, own(group="staff"))


def test_deleting_the_own_account_is_a_lockout() -> None:
    assert lockout_reason("openvpn", None, [Effect("user", "openvpn", SAFE, None)])


def test_deleting_the_own_group_is_a_lockout() -> None:
    effect = Effect("group", "Admins", PLAIN, None)
    assert lockout_reason("openvpn", "admins", [effect])


def test_a_harmless_change_of_the_own_account_passes() -> None:
    assert lockout_reason("openvpn", None, own(totp=True)) is None


def test_an_unrelated_user_passes_the_lockout_guard() -> None:
    effects = [
        Effect("user", "alice", PLAIN, {**PLAIN, "deny": True}),
        Effect("user", "bob", PLAIN, None),
        Effect("group", "staff", PLAIN, None),
    ]
    assert lockout_reason("openvpn", "admins", effects) is None


def test_a_group_named_like_the_own_account_is_not_the_own_account() -> None:
    effect = Effect("group", "openvpn", PLAIN, None)
    assert lockout_reason("openvpn", None, [effect]) is None


def test_the_first_lockout_in_a_list_is_reported() -> None:
    effects = [Effect("user", "alice", PLAIN, None), *own(deny=True)]
    assert lockout_reason("openvpn", None, effects)


def test_auto_refuses_an_admin_grant_by_change() -> None:
    effect = Effect("user", "alice", PLAIN, {**PLAIN, "admin": True})
    assert auto_limit_reason([effect]) == "user alice would become an administrator"


def test_auto_refuses_an_admin_grant_by_create() -> None:
    effect = Effect("group", "ops", None, {**PLAIN, "admin": True})
    assert auto_limit_reason([effect]) == "group ops would become an administrator"


def test_auto_allows_an_existing_admin_to_stay_admin() -> None:
    assert (
        auto_limit_reason([Effect("user", "root", SAFE, {**SAFE, "deny": True})])
        is None
    )


def test_auto_refuses_switching_mfa_off() -> None:
    before = {**PLAIN, "totp": True}
    effect = Effect("user", "alice", before, {**before, "totp": False})
    assert auto_limit_reason([effect]) == "MFA would be switched off for user alice"


def test_auto_allows_a_new_user_without_mfa() -> None:
    assert auto_limit_reason([Effect("user", "alice", None, PLAIN)]) is None


def test_auto_refuses_an_authentication_method_change() -> None:
    effect = Effect("group", "staff", PLAIN, {**PLAIN, "auth_method": "ldap"})
    assert auto_limit_reason([effect]) == (
        "the authentication method of group staff would change"
    )


def test_auto_refuses_switching_autologin_on() -> None:
    effect = Effect("user", "alice", PLAIN, {**PLAIN, "autologin": True})
    assert auto_limit_reason([effect]) == (
        "autologin would be switched on for user alice"
    )
    created = Effect("user", "bot", None, {**PLAIN, "autologin": True})
    assert auto_limit_reason([created]) == "autologin would be switched on for user bot"


def test_auto_allows_deletes_and_harmless_changes() -> None:
    effects = [
        Effect("user", "alice", {**PLAIN, "totp": True}, None),
        Effect("user", "bob", PLAIN, {**PLAIN, "deny": True, "totp": True}),
    ]
    assert auto_limit_reason(effects) is None


def test_auto_reports_the_first_refused_item() -> None:
    effects = [
        Effect("user", "bob", PLAIN, {**PLAIN, "deny": True}),
        Effect("user", "eve", PLAIN, {**PLAIN, "admin": True}),
    ]
    assert auto_limit_reason(effects) == "user eve would become an administrator"


@pytest.mark.parametrize("field", ["deny", "deny_web", "admin", "auth_method"])
def test_an_unknown_value_that_decides_the_own_sign_in_is_a_lockout(
    field: str,
) -> None:
    reason = lockout_reason("openvpn", None, own(**{field: UNKNOWN}))
    assert reason == f"the {field} of the own account after this change is not known"


def test_the_own_account_in_another_letter_case_is_also_protected_from_unknown() -> (
    None
):
    effect = Effect("user", "OpenVPN", SAFE, {**SAFE, "auth_method": UNKNOWN})
    assert lockout_reason("openvpn", None, [effect])


@pytest.mark.parametrize("field", ["totp", "autologin"])
def test_an_unknown_value_that_cannot_lock_the_own_account_out_passes(
    field: str,
) -> None:
    assert lockout_reason("openvpn", None, own(**{field: UNKNOWN})) is None


def test_an_unknown_value_of_another_user_is_not_a_lockout() -> None:
    for field in GUARDED:
        effect = Effect("user", "bob", PLAIN, {**PLAIN, field: UNKNOWN})
        assert lockout_reason("openvpn", None, [effect]) is None, field


@pytest.mark.parametrize("field", GUARDED)
def test_an_unknown_value_is_refused_in_auto_mode_for_any_target(field: str) -> None:
    for kind in ("user", "group"):
        effect = Effect(kind, "bob", PLAIN, {**PLAIN, field: UNKNOWN})
        assert auto_limit_reason([effect]) == (
            f"the {field} of {kind} bob after this change is not known"
        )


def test_an_unknown_value_of_a_new_user_is_refused_in_auto_mode() -> None:
    effect = Effect("user", "new", None, {**PLAIN, "totp": UNKNOWN})
    assert auto_limit_reason([effect]) == (
        "the totp of user new after this change is not known"
    )


def test_newly_denied_lists_users_whose_deny_goes_from_false_to_true() -> None:
    effects = [
        Effect("user", "bob", PLAIN, {**PLAIN, "deny": True}),
        Effect("user", "eve", {**PLAIN, "deny": True}, {**PLAIN, "deny": True}),
    ]
    assert newly_denied(effects) == ["bob"]


def test_newly_denied_counts_an_unknown_deny_as_possibly_blocked() -> None:
    effects = [Effect("user", "bob", PLAIN, {**PLAIN, "deny": UNKNOWN})]
    assert newly_denied(effects) == ["bob"]


def test_newly_denied_leaves_out_everything_that_has_no_session_to_keep() -> None:
    denied = {**PLAIN, "deny": True}
    effects = [
        Effect("user", "created", None, denied),
        Effect("user", "deleted", PLAIN, None),
        Effect("user", "unblocked", denied, PLAIN),
        Effect("user", "untouched", PLAIN, {**PLAIN, "totp": True}),
        Effect("group", "staff", PLAIN, denied),
    ]
    assert newly_denied(effects) == []


def test_newly_denied_keeps_the_order_of_the_effects() -> None:
    denied = {**PLAIN, "deny": True}
    effects = [Effect("user", name, PLAIN, denied) for name in ("zoe", "adam", "mia")]
    assert newly_denied(effects) == ["zoe", "adam", "mia"]
