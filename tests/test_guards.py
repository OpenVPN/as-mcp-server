"""Refusals decided before any write: self-lockout and the automatic-mode limits."""

from __future__ import annotations

from as_mcp_server.guards import Effect, auto_limit_reason, lockout_reason

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
