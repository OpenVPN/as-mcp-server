"""What a user or group record will look like after a change, before it is written."""

from __future__ import annotations

import copy
from typing import Any

import pytest

from as_mcp_server.effective import (
    GUARDED,
    INHERITABLE,
    UNKNOWN,
    CannotCompute,
    group_after,
    server_wide,
    snapshot,
    user_after,
)
from tests.conftest import load_fixture

VALUES = {
    "deny": False,
    "deny_web": False,
    "admin": False,
    "auth_method": "local",
    "totp": False,
    "autologin": False,
}
BASE = dict(VALUES)


def prop(value: Any, inherited: bool = True, source: str = "configuration") -> dict:
    return {"value": value, "inherited": inherited, "inherited_source_type": source}


def own(value: Any) -> dict:
    return prop(value, inherited=False)


def from_group(value: Any) -> dict:
    return {**prop(value, source="group"), "inherited_source_name": "staff"}


def record(name: str = "alice", group: str | None = None, **props: dict) -> dict:
    result: dict[str, Any] = {"name": name}
    result.update({field: prop(value) for field, value in VALUES.items()})
    result.update(props)
    if group is not None:
        result["group"] = group
    return result


def state(**values: Any) -> dict:
    return {**VALUES, **values}


def test_a_snapshot_holds_the_effective_guarded_values_and_the_group() -> None:
    user = record(group="staff", totp=own(True), admin=from_group(True))
    assert snapshot(user) == {**state(totp=True, admin=True), "group": "staff"}


def test_a_snapshot_of_a_record_without_a_group_has_group_none() -> None:
    assert snapshot(record())["group"] is None


def test_a_record_without_a_guarded_field_cannot_be_computed() -> None:
    with pytest.raises(CannotCompute):
        snapshot({"name": "x"})


def test_a_guarded_field_that_is_not_a_property_object_cannot_be_computed() -> None:
    with pytest.raises(CannotCompute):
        snapshot({**record(), "totp": True})


def test_the_stand_fixtures_can_be_snapshotted() -> None:
    _, users = load_fixture("users_list")
    _, groups = load_fixture("groups_list")
    for item in users["profiles"] + groups["profiles"]:
        assert set(snapshot(item)) == {*GUARDED, "group"}


def test_server_wide_values_come_from_records_that_inherit_from_the_server() -> None:
    records = [
        record(auth_method=prop("pam"), totp=own(True), admin=from_group(True)),
        record(auth_method=prop("pam"), totp=prop(False, source="implicit_default")),
    ]
    base = server_wide(records)
    assert base["auth_method"] == "pam"
    assert base["totp"] is False
    assert base["admin"] is False


def test_server_wide_skips_own_and_group_values() -> None:
    records = [{"name": "bob", "totp": own(True), "admin": from_group(True)}]
    assert server_wide(records) == {}


def test_server_wide_ignores_the_default_record() -> None:
    """Measured 2026-11-12: with auth.module.type=pam every inheriting record
    reports pam, while /users/defaultuser still reports local."""
    default = record(name="__DEFAULT__", auth_method=prop("local"))
    assert server_wide([default]) == {}


def test_a_changed_field_takes_the_new_value() -> None:
    assert user_after(record(), {"deny": True}, [], None, BASE)["deny"] is True


def test_a_change_set_to_none_is_not_a_change() -> None:
    user = record(totp=own(True))
    assert user_after(user, {"totp": None}, [], None, BASE)["totp"] is True


def test_a_user_moved_into_an_admin_group_inherits_admin() -> None:
    user = record(group="staff", admin=from_group(False))
    after = user_after(user, {"group": "admins"}, [], state(admin=True), BASE)
    assert after["admin"] is True
    assert after["group"] == "admins"


def test_an_own_value_survives_a_group_move() -> None:
    user = record(group="staff", totp=own(True))
    after = user_after(user, {"group": "other"}, [], state(totp=False), BASE)
    assert after["totp"] is True


def test_reset_to_inherited_takes_the_group_value() -> None:
    user = record(group="staff", totp=own(True))
    assert user_after(user, {}, ["totp"], state(totp=False), BASE)["totp"] is False


def test_reset_without_a_group_takes_the_server_wide_value() -> None:
    user = record(auth_method=own("local"))
    after = user_after(user, {}, ["auth_method"], None, {"auth_method": "pam"})
    assert after["auth_method"] == "pam"


def test_a_reset_without_a_known_server_wide_value_is_unknown_not_an_error() -> None:
    user = record(totp=own(True))
    after = user_after(user, {}, ["totp"], None, {})
    assert after["totp"] is UNKNOWN
    assert {field: after[field] for field in GUARDED if field != "totp"} == {
        field: VALUES[field] for field in GUARDED if field != "totp"
    }


def test_a_new_user_without_a_known_server_wide_value_is_unknown_there() -> None:
    after = user_after(None, {"deny": True}, [], None, {"admin": False})
    assert after["deny"] is True and after["admin"] is False
    assert after["totp"] is UNKNOWN and after["auth_method"] is UNKNOWN


def test_a_value_inherited_from_the_server_stays_without_a_base() -> None:
    user = record(auth_method=prop("pam"))
    assert user_after(user, {"deny": True}, [], None, {})["auth_method"] == "pam"


def test_a_user_in_a_group_needs_the_group_state() -> None:
    user = record(group="staff", admin=from_group(True))
    with pytest.raises(CannotCompute):
        user_after(user, {"deny": True}, [], None, BASE)


def test_a_member_follows_a_change_of_its_group() -> None:
    user = record(group="staff", auth_method=from_group("local"))
    after = user_after(user, {}, [], state(auth_method="ldap"), BASE)
    assert after["auth_method"] == "ldap"


def test_a_new_user_takes_changes_then_the_group_then_the_server() -> None:
    in_group = user_after(None, {"group": "admins"}, [], state(admin=True), BASE)
    assert in_group["admin"] is True and in_group["group"] == "admins"
    alone = user_after(None, {"deny": True}, [], None, BASE)
    assert alone == {**state(deny=True), "group": None}


def test_a_group_keeps_own_values_and_takes_changes() -> None:
    group = record(name="staff", totp=own(True))
    after = group_after(group, {"admin": True}, [], BASE)
    assert after["totp"] is True and after["admin"] is True
    assert after["group"] is None


def test_a_group_reset_takes_the_server_wide_value() -> None:
    group = record(name="staff", totp=own(True))
    assert group_after(group, {}, ["totp"], {"totp": False})["totp"] is False
    assert group_after(group, {}, ["totp"], {})["totp"] is UNKNOWN


def test_a_new_group_takes_changes_then_the_server() -> None:
    assert group_after(None, {"admin": True}, [], BASE) == {
        **state(admin=True),
        "group": None,
    }


def test_a_member_follows_its_group_into_the_unknown() -> None:
    """The group was reset and nobody knows the server-wide value: neither does the
    member that inherits from the group."""
    group = group_after(record(name="staff", totp=own(True)), {}, ["totp"], {})
    member = record(group="staff", totp=from_group(True))
    assert user_after(member, {}, [], group, {})["totp"] is UNKNOWN


def test_an_own_value_is_known_even_when_the_group_value_is_not() -> None:
    group = group_after(record(name="staff", totp=own(True)), {}, ["totp"], {})
    member = record(group="staff", totp=own(False))
    assert user_after(member, {}, [], group, {})["totp"] is False


def test_a_group_state_without_a_field_is_still_a_broken_read() -> None:
    user = record(group="staff", totp=from_group(True))
    with pytest.raises(CannotCompute):
        user_after(user, {}, [], {"deny": False}, BASE)


def test_an_explicitly_set_field_is_not_taken_as_the_server_wide_value() -> None:
    """The shape of tests/fixtures/users_list.json: admin set on the record, the
    source type still filled."""
    set_on_record = record(
        admin={
            "value": True,
            "inherited": False,
            "inherited_source_type": "implicit_default",
        }
    )
    assert "admin" not in server_wide([set_on_record])


def test_records_that_disagree_give_no_server_wide_value() -> None:
    yes, no = record(totp=prop(True)), record(totp=prop(False))
    for records in ([yes, no], [no, yes], [yes, yes, no], [no, yes, yes]):
        base = server_wide(records)
        assert "totp" not in base
        assert base["auth_method"] == "local"  # the fields they agree on stay


def test_one_and_true_are_a_disagreement_not_the_same_value() -> None:
    assert "totp" not in server_wide([record(totp=prop(True)), record(totp=prop(1))])


def test_records_that_agree_give_the_value_once() -> None:
    assert server_wide([record(totp=prop(True)), record(totp=prop(True))])["totp"]


def test_an_incomplete_read_gives_no_server_wide_values() -> None:
    assert server_wide([record(totp=prop(True))], complete=False) == {}


def test_a_field_outside_the_guarded_set_is_read_on_request() -> None:
    with_gateway = record(reroute_gw=prop(True))
    assert "reroute_gw" not in server_wide([with_gateway])
    base = server_wide([with_gateway, record()], fields=INHERITABLE)
    assert base["reroute_gw"] is True
    assert set(base) == {*GUARDED, "reroute_gw"}


def test_unknown_is_one_object_that_equals_nothing_and_has_no_truth() -> None:
    assert repr(UNKNOWN) == "unknown" and str(UNKNOWN) == "unknown"
    assert UNKNOWN != "unknown" and UNKNOWN is not None
    assert UNKNOWN != True and UNKNOWN != False  # noqa: E712
    assert (
        copy.copy(UNKNOWN) is UNKNOWN and copy.deepcopy({"a": UNKNOWN})["a"] is UNKNOWN
    )
    with pytest.raises(TypeError, match="is UNKNOWN"):
        bool(UNKNOWN)
