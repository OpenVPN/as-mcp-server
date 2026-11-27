"""The IPv4 access list of one owner: order, where a new entry goes, what has no
effect. Access Server applies the first entry that matches."""

from __future__ import annotations

from ipaddress import IPv4Network
from typing import Any

import pytest

from as_mcp_server.access_lists import (
    Entry,
    Other,
    Refusal,
    Service,
    hidden,
    insert,
    more_specific,
    parse_list,
    remove,
)
from as_mcp_server.effective import CannotCompute
from as_mcp_server.texts import (
    MSG_CONFLICT_ENTRY,
    MSG_DUPLICATE_ENTRY,
    MSG_NO_SUCH_ENTRY,
)
from tests.conftest import load_fixture

TCP_443 = Service("tcp", 443)
UDP_RANGE = Service("udp", 2000, 2999)
ECHO = Service("icmp", icmp_type="icmp-echo-request")


def allow(network: str, *services: Service, via: str = "route") -> Entry:
    return Entry(True, via, IPv4Network(network), services)  # type: ignore[arg-type]


def deny(network: str, *services: Service, via: str = "route") -> Entry:
    return Entry(False, via, IPv4Network(network), services)  # type: ignore[arg-type]


def test_a_host_is_more_specific_than_its_network() -> None:
    assert more_specific(deny("10.0.0.5/32"), allow("10.0.0.0/24"))
    assert not more_specific(allow("10.0.0.0/24"), deny("10.0.0.5/32"))


def test_a_network_with_services_is_more_specific_than_the_same_network_without() -> (
    None
):
    assert more_specific(allow("10.0.0.0/24", TCP_443), deny("10.0.0.0/24"))
    assert not more_specific(deny("10.0.0.0/24"), allow("10.0.0.0/24", TCP_443))


def test_a_port_inside_a_range_is_more_specific_than_the_range() -> None:
    port = allow("10.0.0.0/24", Service("udp", 2500))
    assert more_specific(port, deny("10.0.0.0/24", UDP_RANGE))
    assert not more_specific(deny("10.0.0.0/24", UDP_RANGE), port)


def test_the_same_traffic_is_not_more_specific() -> None:
    assert not more_specific(
        deny("10.0.0.0/24", TCP_443), allow("10.0.0.0/24", TCP_443)
    )


def test_a_narrower_deny_goes_in_front_of_the_wider_allow() -> None:
    wide = allow("10.0.0.0/24")
    assert insert([wide], deny("10.0.0.5/32"), "alice") == [deny("10.0.0.5/32"), wide]


def test_a_narrower_allow_goes_in_front_of_the_wider_deny() -> None:
    wide = deny("10.0.0.0/24")
    assert insert([wide], allow("10.0.0.5/32"), "alice") == [allow("10.0.0.5/32"), wide]


def test_a_new_entry_goes_right_before_the_first_wider_entry_that_overlaps() -> None:
    other_net = allow("10.9.0.0/16")
    first_wide = allow("10.0.0.0/16")
    second_wide = allow("10.0.0.0/8")
    new = deny("10.0.0.5/32")
    assert insert([other_net, first_wide, second_wide], new, "alice") == [
        other_net,
        new,
        first_wide,
        second_wide,
    ]


def test_a_wider_entry_goes_to_the_end() -> None:
    entries = [deny("10.0.0.5/32"), allow("10.0.0.0/24")]
    assert insert(entries, allow("10.0.0.0/16"), "alice") == [
        *entries,
        allow("10.0.0.0/16"),
    ]


def test_entries_of_other_classes_keep_their_place() -> None:
    group = Other({"type": "group", "accept": True, "groupname": "staff"}, True)
    wide = allow("10.0.0.0/24")
    assert insert([group, wide], deny("10.0.0.5/32"), "alice") == [
        group,
        deny("10.0.0.5/32"),
        wide,
    ]


def test_the_same_entry_twice_is_refused() -> None:
    entries = [allow("10.0.0.0/24", TCP_443, UDP_RANGE)]
    with pytest.raises(Refusal) as refused:
        insert(entries, allow("10.0.0.0/24", UDP_RANGE, TCP_443, via="nat"), "alice")
    assert str(refused.value) == MSG_DUPLICATE_ENTRY.format(
        owner="alice", entry="allow 10.0.0.0/24 tcp/443, udp/2000-2999 (route)"
    )


def test_the_same_network_with_the_opposite_action_is_refused() -> None:
    with pytest.raises(Refusal) as refused:
        insert([allow("10.0.0.0/24")], deny("10.0.0.0/24"), "alice")
    assert str(refused.value) == MSG_CONFLICT_ENTRY.format(
        owner="alice", entry="allow 10.0.0.0/24 (route)"
    )


def test_a_deny_after_a_wider_allow_is_reported_as_hidden() -> None:
    wide = allow("10.0.0.0/24")
    narrow = deny("10.0.0.5/32", TCP_443)
    assert hidden([wide, narrow]) == [(narrow, wide)]


def test_an_entry_is_hidden_only_when_the_earlier_one_covers_all_its_traffic() -> None:
    only_web = allow("10.0.0.0/24", TCP_443)
    assert hidden([only_web, deny("10.0.0.5/32")]) == []
    assert hidden([only_web, deny("10.0.0.5/32", TCP_443)]) == [
        (deny("10.0.0.5/32", TCP_443), only_web)
    ]


def test_a_repeat_with_the_same_action_is_not_reported() -> None:
    assert hidden([allow("10.0.0.0/24"), allow("10.0.0.5/32")]) == []


def test_removing_an_entry_removes_every_copy() -> None:
    keep = allow("10.0.0.0/24")
    gone = deny("10.0.0.5/32", TCP_443, ECHO)
    copy = deny("10.0.0.5/32", ECHO, TCP_443)
    assert remove([gone, keep, copy], gone, "alice") == [keep]


def test_removing_a_missing_entry_is_refused() -> None:
    with pytest.raises(Refusal) as refused:
        remove([allow("10.0.0.0/24")], deny("10.0.0.5/32"), "alice")
    assert str(refused.value) == MSG_NO_SUCH_ENTRY.format(
        owner="alice", entry="deny 10.0.0.5/32 (route)"
    )


@pytest.mark.parametrize("fixture", ["access_lists", "access_lists_3_1_0"])
def test_parse_and_api_round_trip_the_captured_lists(fixture: str) -> None:
    _, body = load_fixture(fixture)
    for item in body["profiles"]:
        if item["type"] != "access_to_ipv4":
            continue
        kind = "user" if "username" in item else "group"
        owner = item["username"] if kind == "user" else item["groupname"]
        parsed = parse_list(body, owner, kind)
        assert item in [entry.api(owner, kind) for entry in parsed]


def test_alice_has_two_allows_and_a_deny_in_server_order() -> None:
    _, body = load_fixture("access_lists")
    assert parse_list(body, "alice", "user") == [
        allow("10.30.0.5/32", via="nat"),
        allow("10.40.0.0/24", TCP_443, UDP_RANGE, ECHO),
        deny("10.40.0.99/32"),
    ]
    assert [e.label() for e in parse_list(body, "alice", "user")] == [
        "allow 10.30.0.5/32 (nat)",
        "allow 10.40.0.0/24 tcp/443, udp/2000-2999, icmp-echo-request (route)",
        "deny 10.40.0.99/32 (route)",
    ]


def test_access_from_entries_are_not_part_of_the_list() -> None:
    _, body = load_fixture("access_lists")
    (group,) = parse_list(body, "bob", "user")
    assert isinstance(group, Other) and group.label() == "allow group staff"
    assert parse_list(body, "mfa-admin", "user") == []


def test_a_user_and_a_group_with_the_same_name_are_different_owners() -> None:
    body: dict[str, Any] = {
        "profiles": [
            {
                "groupname": "alice",
                "type": "access_to_ipv4",
                "access_route": {"type": "all_vpn_clients", "accept": True},
            }
        ]
    }
    assert parse_list(body, "alice", "user") == []
    assert len(parse_list(body, "alice", "group")) == 1


def test_only_the_class_all_cannot_be_written_back() -> None:
    def other(route: dict[str, Any]) -> Other:
        body = {
            "profiles": [
                {"username": "u", "type": "access_to_ipv4", "access_route": route}
            ]
        }
        (parsed,) = parse_list(body, "u", "user")
        assert isinstance(parsed, Other)
        return parsed

    assert other({"type": "all", "accept": True}).writable is False
    assert other({"type": "all_vpn_clients", "accept": True}).writable is True
    assert other({"type": "user", "accept": False, "username": "x"}).writable is True
    assert other({"type": "all", "accept": True}).label() == "allow all"


def test_icmp_any_and_a_protocol_without_ports_cover_their_whole_protocol() -> None:
    assert more_specific(
        deny("10.0.0.0/24", ECHO),
        allow("10.0.0.0/24", Service("icmp", icmp_type="icmp-any")),
    )
    assert more_specific(
        deny("10.0.0.0/24", TCP_443), allow("10.0.0.0/24", Service("tcp"))
    )
    assert not more_specific(
        deny("10.0.0.0/24", TCP_443), allow("10.0.0.0/24", Service("udp"))
    )
    assert Service("tcp").label() == "tcp"
    assert Service("tcp", 80, 80).label() == "tcp/80"


@pytest.mark.parametrize(
    "subnet",
    [
        {"ipv6": True, "netip": "fd00::", "prefix_length": 64, "service": []},
        {"ipv6": False, "netip": "10.0.0.5", "prefix_length": 24, "service": []},
        {"ipv6": False, "netip": "not-an-address", "prefix_length": 24},
    ],
)
def test_a_server_entry_the_model_cannot_read_is_kept_as_it_is(subnet: dict) -> None:
    route = {"type": "route", "accept": True, "subnet": subnet}
    body = {
        "profiles": [{"username": "u", "type": "access_to_ipv4", "access_route": route}]
    }
    assert parse_list(body, "u", "user") == [Other(route, writable=True)]


@pytest.mark.parametrize(
    "body",
    [
        [],
        {"profiles": "none"},
        {
            "profiles": [
                {"username": "u", "type": "access_to_ipv4", "access_route": "x"}
            ]
        },
    ],
)
def test_an_answer_in_an_unknown_shape_cannot_be_computed(body: Any) -> None:
    with pytest.raises(CannotCompute):
        parse_list(body, "u", "user")
