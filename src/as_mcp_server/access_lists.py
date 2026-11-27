"""The IPv4 access list of one owner (`access_to_ipv4`), as Access Server keeps it.

Access Server applies the first entry that matches, so the order is part of the
list. This module says where a new entry goes, which entries have no effect, and
what a removal leaves. It never talks to the server.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from ipaddress import IPv4Network
from typing import Any, Literal

from as_mcp_server.effective import CannotCompute
from as_mcp_server.preview import clean
from as_mcp_server.texts import (
    MSG_CONFLICT_ENTRY,
    MSG_DUPLICATE_ENTRY,
    MSG_NO_SUCH_ENTRY,
)

Kind = Literal["user", "group"]
OWNER_KEY: dict[Kind, str] = {"user": "username", "group": "groupname"}
LIST_TYPE = "access_to_ipv4"
ALL_PORTS = (0, 65535)
ANY_ICMP = "icmp-any"


class Refusal(Exception):
    """A change the list cannot take; the message is the finished refusal."""


@dataclass(frozen=True)
class Service:
    """One item of `subnet.service`."""

    protocol: Literal["tcp", "udp", "icmp"]
    start_port: int | None = None
    end_port: int | None = None
    icmp_type: str | None = None

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> Service:
        return cls(
            raw["protocol"], raw.get("start_port"), raw.get("end_port"), raw.get("type")
        )

    def api(self) -> dict[str, Any]:
        raw: dict[str, Any] = {"protocol": self.protocol}
        if self.start_port is not None:
            raw["start_port"] = self.start_port
        if self.end_port is not None:
            raw["end_port"] = self.end_port
        if self.icmp_type is not None:
            raw["type"] = self.icmp_type
        return raw

    def ports(self) -> tuple[int, int]:
        if self.start_port is None:
            return ALL_PORTS
        return self.start_port, self.end_port or self.start_port

    def covers(self, other: Service) -> bool:
        if self.protocol != other.protocol:
            return False
        if self.protocol == "icmp":
            return self.icmp_type in (None, ANY_ICMP, other.icmp_type)
        low, high = self.ports()
        other_low, other_high = other.ports()
        return low <= other_low and other_high <= high

    def label(self) -> str:
        if self.protocol == "icmp":
            return self.icmp_type or "icmp"
        if self.start_port is None:
            return self.protocol
        if self.end_port is None or self.end_port == self.start_port:
            return f"{self.protocol}/{self.start_port}"
        return f"{self.protocol}/{self.start_port}-{self.end_port}"


@dataclass(frozen=True)
class Entry:
    """An entry of class `route` or `nat`. Services keep the server's order; an
    empty tuple means all traffic."""

    accept: bool
    via: Literal["route", "nat"]
    network: IPv4Network
    services: tuple[Service, ...] = ()

    def traffic(self) -> tuple[IPv4Network, frozenset[Service]]:
        return self.network, frozenset(self.services)

    def api(self, owner: str, kind: Kind) -> dict[str, Any]:
        return {
            OWNER_KEY[kind]: owner,
            "access_route": {
                "type": self.via,
                "accept": self.accept,
                "subnet": {
                    "ipv6": False,
                    "netip": str(self.network.network_address),
                    "prefix_length": self.network.prefixlen,
                    "service": [service.api() for service in self.services],
                },
            },
            "type": LIST_TYPE,
        }

    def label(self) -> str:
        action = "allow" if self.accept else "deny"
        services = ", ".join(service.label() for service in self.services)
        middle = f" {services}" if services else ""
        return f"{action} {self.network}{middle} ({self.via})"


@dataclass(frozen=True)
class Other:
    """An entry this module does not place (class user, group, all, ...). It is
    kept as the server returned it."""

    raw: dict[str, Any]
    writable: bool = True

    def api(self, owner: str, kind: Kind) -> dict[str, Any]:
        return {OWNER_KEY[kind]: owner, "access_route": self.raw, "type": LIST_TYPE}

    def label(self) -> str:
        action = "allow" if self.raw.get("accept") else "deny"
        target = self.raw.get("username") or self.raw.get("groupname")
        kind = str(self.raw.get("type", "unknown"))
        return f"{action} {kind} {target}" if target else f"{action} {kind}"


Item = Entry | Other


def _entry(route: dict[str, Any]) -> Entry | None:
    subnet = route.get("subnet")
    if route.get("type") not in ("route", "nat") or not isinstance(subnet, dict):
        return None
    if subnet.get("ipv6"):
        return None
    try:
        network = IPv4Network(f"{subnet['netip']}/{subnet['prefix_length']}")
        services = tuple(Service.from_api(raw) for raw in subnet.get("service") or [])
    except (KeyError, TypeError, ValueError):
        return None
    if not isinstance(route.get("accept"), bool):
        return None
    return Entry(route["accept"], route["type"], network, services)


def parse_list(body: Any, owner: str, kind: Kind) -> list[Item]:
    """The `access_to_ipv4` entries of one owner, in the server's order, from the
    answer of /userprop/access/list."""
    profiles = body.get("profiles") if isinstance(body, dict) else None
    if not isinstance(profiles, list):
        raise CannotCompute("the access lists came back in an unknown shape")
    items: list[Item] = []
    for raw in profiles:
        if not isinstance(raw, dict) or raw.get("type") != LIST_TYPE:
            continue
        if raw.get(OWNER_KEY[kind]) != owner:
            continue
        route = raw.get("access_route")
        if not isinstance(route, dict):
            raise CannotCompute(f"an entry of {owner} has no readable access_route")
        entry = _entry(route)
        if entry is not None and entry.api(owner, kind) == raw:
            items.append(entry)
        else:
            items.append(Other(route, writable=route.get("type") != "all"))
    return items


def _covers(earlier: Entry, later: Entry) -> bool:
    """Every packet of `later`'s services is in `earlier`'s services."""
    if not earlier.services:
        return True
    if not later.services:
        return False
    return all(
        any(mine.covers(theirs) for mine in earlier.services)
        for theirs in later.services
    )


def more_specific(a: Entry, b: Entry) -> bool:
    """`a` matches part of what `b` matches, and not all of it."""
    if a.network != b.network:
        return a.network.subnet_of(b.network)
    return _covers(b, a) and not _covers(a, b)


def insert(entries: Sequence[Item], new: Entry, owner: str) -> list[Item]:
    """The list with `new` right before the first wider entry that overlaps it,
    or at the end."""
    for entry in entries:
        if isinstance(entry, Entry) and entry.traffic() == new.traffic():
            text = (
                MSG_DUPLICATE_ENTRY
                if entry.accept == new.accept
                else MSG_CONFLICT_ENTRY
            )
            raise Refusal(text.format(owner=clean(owner), entry=entry.label()))
    for index, entry in enumerate(entries):
        if (
            isinstance(entry, Entry)
            and entry.network.overlaps(new.network)
            and more_specific(new, entry)
        ):
            return [*entries[:index], new, *entries[index:]]
    return [*entries, new]


def remove(entries: Sequence[Item], gone: Entry, owner: str) -> list[Item]:
    """The list without any copy of `gone` (the server removes every copy)."""
    kept = [
        entry
        for entry in entries
        if not (
            isinstance(entry, Entry)
            and entry.traffic() == gone.traffic()
            and (entry.accept, entry.via) == (gone.accept, gone.via)
        )
    ]
    if len(kept) == len(entries):
        raise Refusal(MSG_NO_SUCH_ENTRY.format(owner=clean(owner), entry=gone.label()))
    return kept


def hidden(entries: Sequence[Item]) -> list[tuple[Entry, Entry]]:
    """(entry, the earlier entry with the opposite action that takes all its
    traffic) for each entry that has no effect."""
    found: list[tuple[Entry, Entry]] = []
    for index, later in enumerate(entries):
        if not isinstance(later, Entry):
            continue
        for earlier in entries[:index]:
            if (
                isinstance(earlier, Entry)
                and earlier.accept != later.accept
                and earlier.network.supernet_of(later.network)
                and _covers(earlier, later)
            ):
                found.append((later, earlier))
                break
    return found
