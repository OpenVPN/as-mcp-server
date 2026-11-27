"""Write-mode tools for access control: `modify_access_list`, `save_access_ruleset`,
`delete_access_rulesets`, `assign_access_ruleset`, `modify_access_rules`.

Measured on 3.1.0 and 3.2.4: the first entry of an access list that matches wins;
one /userprop/access/set request with items_remove and items_append reorders a
list (the removal first, every copy of an item); a changed access list applies
only after a warm restart.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from ipaddress import IPv4Network
from typing import Annotated, Any, Literal

from fastmcp import Context, FastMCP
from fastmcp.exceptions import ToolError
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from as_mcp_server.access_lists import (
    ICMP_TYPES,
    Entry,
    Item,
    Kind,
    Refusal,
    Service,
    hidden,
    identity,
    insert,
    parse_list,
    remove,
    rewrite,
)
from as_mcp_server.client import AccessServerClient, RequestTimeoutError
from as_mcp_server.effective import DEFAULT_RECORD, CannotCompute
from as_mcp_server.preview import PreviewItem, clean
from as_mcp_server.texts import (
    AUTO_ACCESS,
    MSG_LAST_OWNER,
    MSG_NO_ACCESS_CHANGE,
    MSG_NO_SUCH_RULESET,
    NOTE_ACCESS_LIST_RESTART,
    NOTE_DOMAIN_DENY,
    NOTE_DOMAIN_RULES,
    NOTE_GLOBAL_IP,
    WARN_HIDDEN,
)
from as_mcp_server.writes import (
    DESTRUCTIVE,
    MAX_ITEMS,
    RESULT_HELP,
    WRITE,
    Own,
    Partial,
    Plan,
    WriteDeps,
    kind_of,
    run_write,
)

TOOLS = (
    "modify_access_list",
    "save_access_ruleset",
    "delete_access_rulesets",
    "assign_access_ruleset",
    "modify_access_rules",
)
PRIVATE_ACCESS = "vpn.server.routing.private_access"
MSG_NO_DEFAULT_VIA = (
    "Refused: give via (route or nat) for every new entry: the server setting "
    f"{PRIVATE_ACCESS} is {{value}}, so there is no default."
)
MSG_DEFAULT_OWNER = (
    f"Refused: {DEFAULT_RECORD} is not a user or group, and Access Server does not "
    f"return an access list written for it. {NOTE_GLOBAL_IP}"
)
RESTART_EFFECT = "takes effect only after a warm restart (warm_restart)"
MSG_RULESET_NO_OWNER = (
    "Refused: a new rule set needs an owner (owners or all_users): Access Server "
    "does not list a rule set without an owner."
)
MSG_RULESET_USE_ASSIGN = (
    "Refused: owners, all_users and position are for a new rule set. To change who "
    "has rule set {id}, use assign_access_ruleset."
)
MSG_DEFAULT_AS_OWNER = (
    f"Refused: {DEFAULT_RECORD} is not a user or group; for a rule set of all users "
    "give all_users=true."
)
MSG_RULESET_NOTHING = (
    "Refused: nothing to change; rule set {id} already has this name and comment."
)
MSG_POSITION_TAKEN = (
    "Refused: {owner} already has rule set {name} (id {id}) at position {position}, "
    "and which of two rule sets at one position applies first is not known. Give "
    "another position."
)
MSG_RULESET_UNLISTED = (
    "Refused: rule set {id} has no owner, so Access Server does not show its name "
    "and comment. Give it an owner with assign_access_ruleset first, or delete it "
    "with delete_access_rulesets."
)
MSG_UNASSIGN_POSITION = (
    "Refused: position is for giving a rule set, not for taking it away."
)
MAX_RULESET_NAME = 128
MAX_RULESET_COMMENT = 200
MSG_RULESET_NAME = (
    f"Refused: a rule set name is 1 to {MAX_RULESET_NAME} printable characters on "
    "one line."
)
MSG_RULESET_COMMENT = (
    f"Refused: a comment is at most {MAX_RULESET_COMMENT} printable characters on "
    "one line."
)
# Of the rule sets of one owner the lower position applies first (measured); a new
# one goes after the last, one step further.
POSITION_STEP = 100
RULE_TYPE = "domain_routing"
# The match types measured on 3.1.0 and 3.2.4; the not_* ones of the API are not.
MatchType = Literal["domain", "subdomain", "domain_or_subdomain"]
RuleAction = Literal["route", "nat", "deny", "bypass"]
PHRASES = {
    "domain": "{domain}",
    "subdomain": "subdomains of {domain}",
    "domain_or_subdomain": "{domain} and its subdomains",
}
MSG_NO_RULE_CHANGE = (
    "Refused: nothing to change. Give at least one rule to add, update or delete."
)
MSG_BYPASS = (
    "bypass answers the name with its real address and opens nothing through the "
    "VPN for it (measured with a full tunnel)."
)
_LABEL = re.compile(r"[a-z0-9-]{1,63}")
IcmpType = Literal[ICMP_TYPES]  # type: ignore[valid-type]


class ServiceParam(BaseModel):
    model_config = ConfigDict(extra="forbid")

    protocol: Literal["tcp", "udp", "icmp"]
    port: int | None = Field(
        None, ge=1, le=65535, description="tcp and udp: the port, or the first port"
    )
    end_port: int | None = Field(
        None, ge=1, le=65535, description="tcp and udp: the last port of a range"
    )
    icmp_type: IcmpType | None = Field(None, description="icmp only: the ICMP type")

    @model_validator(mode="after")
    def _fits_protocol(self) -> ServiceParam:
        if self.protocol == "icmp":
            if self.icmp_type is None or self.port is not None or self.end_port:
                raise ValueError("icmp needs icmp_type and takes no port")
        else:
            if self.port is None or self.icmp_type is not None:
                raise ValueError(f"{self.protocol} needs port and takes no icmp_type")
            if self.end_port is not None and self.end_port < self.port:
                raise ValueError("end_port is lower than port")
        return self

    def service(self) -> Service:
        return Service(self.protocol, self.port, self.end_port, self.icmp_type)


class EntryParam(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subnet: str = Field(
        description="IPv4 address (one host) or network in CIDR form, such as "
        "10.0.0.0/24; the host bits must be zero"
    )
    allow: bool = Field(description="true allows the traffic, false denies it")
    via: Literal["route", "nat"] | None = Field(
        None,
        description=(
            "route: the client's VPN address reaches the network, which needs a "
            "route back; nat: Access Server translates it. Omit to use the server "
            f"setting {PRIVATE_ACCESS}."
        ),
    )
    services: list[ServiceParam] = Field(
        default_factory=list,
        max_length=MAX_ITEMS,
        description="Limit the entry to these services; empty means all traffic.",
    )

    @field_validator("subnet")
    @classmethod
    def _ipv4_network(cls, value: str) -> str:
        try:
            IPv4Network(value)
        except ValueError as exc:
            raise ValueError(
                f"{value} is not an IPv4 address or network with zero host bits"
            ) from exc
        return value

    def entry(self, default_via: str | None) -> Entry:
        via = self.via or default_via
        if via not in ("route", "nat"):
            raise ToolError(MSG_NO_DEFAULT_VIA.format(value=clean(default_via)))
        return Entry(
            self.allow,
            via,  # type: ignore[arg-type]
            IPv4Network(self.subnet),
            tuple(service.service() for service in self.services),
        )


def _domain(value: str) -> str:
    """A domain name as Access Server compares it: lower case, no trailing dot."""
    name = value.lower()
    if name.endswith("."):
        name = name[:-1]
    if name.startswith("*."):
        under = name[2:]
        raise ValueError(
            f"{value} is not a domain name: for the names under {under} give "
            f"{under} with match_type subdomain"
        )
    if not name.isascii():
        raise ValueError(f"{value} is not ASCII: give the punycode form (xn--...)")
    if len(name) > 253 or not all(_LABEL.fullmatch(part) for part in name.split(".")):
        raise ValueError(
            f"{value} is not a domain name: labels of letters, digits and hyphens, "
            "1 to 63 characters each, 253 characters in all"
        )
    return name


def _one_line(value: str | None) -> str | None:
    if value is not None and not value.isprintable():
        raise ValueError("a comment is printable characters on one line")
    return value


class RuleParam(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain: str = Field(
        min_length=1,
        max_length=254,
        description="Domain name, such as intranet.example.com; no wildcards.",
    )
    match_type: MatchType = Field(
        "domain_or_subdomain",
        description=(
            "domain: only this name; subdomain: the names under it; "
            "domain_or_subdomain: both."
        ),
    )
    action: RuleAction = Field(
        description="nat, route, deny or bypass (see the tool description)."
    )
    position: int | None = Field(
        None,
        ge=1,
        description="Lower applies first. Omit to put it after the last rule.",
    )
    comment: str = Field("", max_length=MAX_RULESET_COMMENT)

    @field_validator("domain")
    @classmethod
    def _valid_domain(cls, value: str) -> str:
        return _domain(value)

    @field_validator("comment")
    @classmethod
    def _valid_comment(cls, value: str) -> str:
        return _one_line(value)  # type: ignore[return-value]


class RuleUpdateParam(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: int = Field(ge=1, description="Id of the rule (from list_access_rules).")
    domain: str | None = Field(None, min_length=1, max_length=254)
    match_type: MatchType | None = None
    action: RuleAction | None = None
    position: int | None = Field(None, ge=1)
    comment: str | None = Field(None, max_length=MAX_RULESET_COMMENT)

    @field_validator("domain")
    @classmethod
    def _valid_domain(cls, value: str | None) -> str | None:
        return None if value is None else _domain(value)

    @field_validator("comment")
    @classmethod
    def _valid_comment(cls, value: str | None) -> str | None:
        return _one_line(value)


@dataclass(frozen=True)
class _Change:
    owner: str
    add: tuple[EntryParam, ...]
    remove: tuple[EntryParam, ...]


@dataclass
class _ModifyAccessList:
    tool: str = "modify_access_list"
    action: str = "Change access list"
    note: str = NOTE_ACCESS_LIST_RESTART
    needs_output_dir: bool = False
    refuse_untested: bool = True
    # The list as last read and as planned; one call changes one owner.
    _current: list[Item] = field(default_factory=list)
    _wanted: list[Item] = field(default_factory=list)
    _kind: Kind = "user"

    def key(self, item: _Change) -> str:
        return item.owner.casefold()

    def target(self, item: _Change) -> str:
        return item.owner

    async def read(self, client: AccessServerClient, item: _Change) -> dict[str, Any]:
        if item.owner == DEFAULT_RECORD:
            raise ToolError(MSG_DEFAULT_OWNER)
        kind = await kind_of(client, item.owner)
        if kind is None:
            raise _unknown_owner(item.owner)
        self._kind = kind  # type: ignore[assignment]
        key = "users" if kind == "user" else "groups"
        body = {key: [item.owner], "filters": {"object_type": kind}}
        answer = await client.post("/userprop/access/list", body)
        self._current = parse_list(answer, item.owner, self._kind)
        return {
            "kind": kind,
            "access_list": [entry.label() for entry in self._current],
            "default_via": await _default_via(client),
        }

    def plan(self, item: _Change, before: dict[str, Any], own: Own) -> Plan:
        if not item.add and not item.remove:
            raise ToolError(MSG_NO_ACCESS_CHANGE)
        current = list(self._current)
        wanted = list(current)
        lines: list[str] = []
        try:
            for param in item.remove:
                gone = param.entry(before["default_via"])
                wanted = remove(wanted, gone, item.owner)
                lines.append(f"removes {gone.label()}")
            for param in item.add:
                new = param.entry(before["default_via"])
                wanted = insert(wanted, new, item.owner)
                lines.append(_placed(wanted, new))
            removed, appended = rewrite(current, wanted, item.owner, self._kind)
        except Refusal as exc:
            raise ToolError(str(exc)) from exc
        if not removed and not appended:
            raise ToolError(MSG_NO_ACCESS_CHANGE)
        self._wanted = wanted
        warnings = _warnings(wanted)
        return Plan(
            PreviewItem(
                item.owner,
                {"entries": (len(current), len(wanted))},
                (*lines, RESTART_EFFECT, *warnings),
                order_after=tuple(entry.label() for entry in wanted),
            ),
            auto_reason=AUTO_ACCESS,
        )

    async def apply(
        self, client: AccessServerClient, item: _Change, before: dict[str, Any]
    ) -> dict[str, Any]:
        removed, appended = rewrite(self._current, self._wanted, item.owner, self._kind)
        body: dict[str, Any] = {}
        if removed:
            body["items_remove"] = removed
        if appended:
            body["items_append"] = appended
        await client.post("/userprop/access/set", body)
        return {"warnings": _warnings(self._wanted)}

    async def verify(self, client: AccessServerClient, item: _Change) -> dict[str, Any]:
        state = await self.read(client, item)
        if [identity(e) for e in self._current] != [identity(e) for e in self._wanted]:
            raise Partial(
                ["written"],
                "the server stored another order: "
                + "; ".join(state["access_list"])
                + ". Read it with list_access_lists and fix the order in the Admin "
                "UI before a warm restart",
            )
        return state


@dataclass(frozen=True)
class _RuleSet:
    name: str
    comment: str | None
    ruleset_id: int | None
    owners: tuple[str, ...]
    all_users: bool
    position: int | None


@dataclass
class _SaveAccessRuleset:
    """A new rule set with its owners, or a new name and comment for one."""

    action: str
    tool: str = "save_access_ruleset"
    note: str = NOTE_DOMAIN_RULES
    needs_output_dir: bool = False
    # A new rule set: who gets it (the name sent -> how it is shown), the rule sets
    # they have, where it goes, and its id once created.
    _holders: dict[str, str] = field(default_factory=dict)
    _taken: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    _same_name: list[Any] = field(default_factory=list)
    _positions: dict[str, int] = field(default_factory=dict)
    _id: int | None = None
    _comment: str = ""

    def key(self, item: _RuleSet) -> str:
        return item.name.casefold()

    def target(self, item: _RuleSet) -> str:
        if item.ruleset_id is None:
            return item.name
        return f"rule set {item.ruleset_id}"

    async def read(self, client: AccessServerClient, item: _RuleSet) -> dict[str, Any]:
        if item.ruleset_id is not None:
            return await self._read_existing(client, item)
        if self._id is not None:
            rows, _ = await _rule_set(client, self._id)
            return _state(self._id, rows)
        _check_text(item)
        if not item.owners and not item.all_users:
            raise ToolError(MSG_RULESET_NO_OWNER)
        holders: dict[str, str] = {}
        for owner in item.owners:
            if owner == DEFAULT_RECORD:
                raise ToolError(MSG_DEFAULT_AS_OWNER)
            if owner in holders:
                raise ToolError(f"Refused: {clean(owner)} is in owners twice.")
            kind = await kind_of(client, owner)
            if kind is None:
                raise _unknown_owner(owner)
            holders[owner] = f"{owner} ({kind})"
        if item.all_users:
            holders[DEFAULT_RECORD] = _owner_label(DEFAULT_RECORD, None)
        self._holders = holders
        self._taken = {
            holder: _rows(await client.post("/access/rulesets/list", {"owner": holder}))
            for holder in holders
        }
        listed = _rows(await client.post("/access/rulesets/list", {}))
        self._same_name = sorted(
            {row.get("id") for row in listed if row.get("name") == item.name}, key=str
        )
        return {
            "exists": False,
            "rule_sets_of_owners": {
                label: [
                    f"{row.get('name')} (id {row.get('id')}) at position "
                    f"{row.get('position')}"
                    for row in self._taken[holder]
                ]
                for holder, label in holders.items()
            },
        }

    async def _read_existing(
        self, client: AccessServerClient, item: _RuleSet
    ) -> dict[str, Any]:
        if item.owners or item.all_users or item.position is not None:
            raise ToolError(MSG_RULESET_USE_ASSIGN.format(id=item.ruleset_id))
        _check_text(item)
        rows, _ = await _rule_set(client, item.ruleset_id)  # type: ignore[arg-type]
        if not rows:
            raise ToolError(MSG_RULESET_UNLISTED.format(id=item.ruleset_id))
        return _state(item.ruleset_id, rows)  # type: ignore[arg-type]

    def plan(self, item: _RuleSet, before: dict[str, Any], own: Own) -> Plan:
        if item.ruleset_id is not None:
            return self._plan_existing(item, before)
        positions: dict[str, int] = {}
        for holder, rows in self._taken.items():
            if item.position is None:
                used = [
                    r["position"] for r in rows if isinstance(r.get("position"), int)
                ]
                positions[holder] = max(used, default=0) + POSITION_STEP
                continue
            clash = next((r for r in rows if r.get("position") == item.position), None)
            if clash is not None:
                raise ToolError(
                    MSG_POSITION_TAKEN.format(
                        owner=clean(_owner_name(holder)),
                        name=clean(clash.get("name")),
                        id=clash.get("id"),
                        position=item.position,
                    )
                )
            positions[holder] = item.position
        self._positions = positions
        self._comment = item.comment or ""
        changes: dict[str, tuple[Any, Any]] = {"name": (None, item.name)}
        if self._comment:
            changes["comment"] = (None, self._comment)
        effects = [
            f"assigned to {self._holders[holder]} at position {position}"
            for holder, position in positions.items()
        ]
        effects.append("it has no rules yet; add them with modify_access_rules")
        effects += [
            f"rule set {other} is also called {item.name}; Access Server allows two "
            "rule sets with one name"
            for other in self._same_name
        ]
        return Plan(
            PreviewItem(item.name, changes, tuple(effects)), auto_reason=AUTO_ACCESS
        )

    def _plan_existing(self, item: _RuleSet, before: dict[str, Any]) -> Plan:
        self._comment = before["comment"] if item.comment is None else item.comment
        changes: dict[str, tuple[Any, Any]] = {}
        if item.name != before["name"]:
            changes["name"] = (before["name"], item.name)
        if self._comment != before["comment"]:
            changes["comment"] = (before["comment"], self._comment)
        if not changes:
            raise ToolError(MSG_RULESET_NOTHING.format(id=item.ruleset_id))
        return Plan(
            PreviewItem(
                f"{before['name']} (id {item.ruleset_id})",
                changes,
                (f"owners keep it: {', '.join(before['owners'])}",),
            ),
            auto_reason=AUTO_ACCESS,
        )

    async def apply(
        self, client: AccessServerClient, item: _RuleSet, before: dict[str, Any]
    ) -> dict[str, Any]:
        if item.ruleset_id is not None:
            body = {"id": item.ruleset_id, "name": item.name, "comment": self._comment}
            await client.post("/access/rulesets/update", body)
            return {}
        created = await client.post(
            "/access/rulesets/add", {"name": item.name, "comment": self._comment}
        )
        new = created.get("id") if isinstance(created, dict) else None
        if not isinstance(new, int) or isinstance(new, bool):
            raise Partial(
                ["created"],
                "Access Server did not return the id of the new rule set, so it was "
                "not given its owners",
            )
        self._id = new
        assign = {
            holder: [{"ruleset_id": new, "position": position}]
            for holder, position in self._positions.items()
        }
        try:
            await client.post("/access/user-rulesets/modify", {"add": assign})
        except RequestTimeoutError:
            raise
        except ToolError as exc:
            try:
                await client.post("/access/rulesets/delete", {"ids": [new]})
            except ToolError as cleanup:
                raise Partial(
                    ["created"],
                    f"{exc} Deleting the new rule set again failed too ({cleanup}): "
                    + _unowned(new),
                    {"id": new},
                ) from cleanup
            raise ToolError(
                f"{exc} The new rule set {new} was deleted again; nothing was changed."
            ) from exc
        return {"id": new}

    async def verify(
        self, client: AccessServerClient, item: _RuleSet
    ) -> dict[str, Any]:
        wanted = item.ruleset_id if item.ruleset_id is not None else self._id
        if wanted is None:
            raise ToolError(
                "the id of the new rule set is not known: Access Server did not "
                "answer the request that creates it"
            )
        rows, _ = await _rule_set(client, wanted)
        state = _state(wanted, rows)
        if item.ruleset_id is None and not rows:
            raise Partial(["created"], _unowned(wanted), {"id": wanted})
        placed = {row.get("owner"): row.get("position") for row in rows}
        if (
            state["name"] != item.name
            or state["comment"] != self._comment
            or (item.ruleset_id is None and placed != self._positions)
        ):
            done = ["written"] if item.ruleset_id is not None else ["created"]
            raise Partial(
                done,
                f"Access Server shows rule set {wanted} as {state['name']!r} with "
                f"comment {state['comment']!r}, owners: "
                + (", ".join(state["owners"]) or "none"),
                {"id": wanted},
            )
        return state


@dataclass
class _DeleteAccessRulesets:
    tool: str = "delete_access_rulesets"
    action: str = "Delete rule set"
    note: str = NOTE_DOMAIN_RULES
    needs_output_dir: bool = False

    def key(self, item: int) -> str:
        return str(item)

    def target(self, item: int) -> str:
        return f"rule set {item}"

    async def read(self, client: AccessServerClient, item: int) -> dict[str, Any]:
        rows, count = await _rule_set(client, item)
        return {**_state(item, rows), "rules": count}

    def plan(self, item: int, before: dict[str, Any], own: Own) -> Plan:
        if before["owners"]:
            owners = f"owners that lose it: {', '.join(before['owners'])}"
        else:
            owners = "it has no owner, so Access Server does not list it or its name"
        count = before["rules"]
        rules = (
            "it has no rules"
            if count == 0
            else "its 1 rule is deleted"
            if count == 1
            else f"its {count} rules are deleted"
        )
        shown = (
            f"rule set {item}"
            if before["name"] is None
            else f"{before['name']} (id {item})"
        )
        return Plan(
            PreviewItem(
                shown,
                {"rule set": ("exists", "deleted")},
                (owners, rules, "cannot be undone"),
            ),
            auto_reason=AUTO_ACCESS,
        )

    async def apply(
        self, client: AccessServerClient, item: int, before: dict[str, Any]
    ) -> dict[str, Any]:
        await client.post("/access/rulesets/delete", {"ids": [item]})
        return {}

    async def verify(self, client: AccessServerClient, item: int) -> dict[str, Any]:
        try:
            await client.post("/access/rules/list", {"ruleset_ids": [item]})
        except ToolError as exc:
            if _gone(exc, item):
                return {"exists": False}
            raise
        raise Partial(["written"], f"Access Server still has rule set {item}")


@dataclass(frozen=True)
class _Owner:
    name: str
    all_users: bool = False

    @property
    def sent(self) -> str:
        return DEFAULT_RECORD if self.all_users else self.name


@dataclass
class _AssignAccessRuleset:
    """Give one rule set to owners, move it at owners that have it, or take it away
    (one request per owner)."""

    ruleset_id: int
    unassign: bool
    position: int | None
    # Every owner this call takes the rule set away from: the last owner is counted
    # over the whole call.
    taken: frozenset[str]
    tool: str = "assign_access_ruleset"
    action: str = "Assign rule set"
    note: str = NOTE_DOMAIN_RULES
    needs_output_dir: bool = False
    # The rows of the rule set as last read, and per owner (the name sent) how it
    # is shown, its other rule sets and the position planned for it.
    _rows: list[dict[str, Any]] = field(default_factory=list)
    _labels: dict[str, str] = field(default_factory=dict)
    _others: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    _planned: dict[str, int] = field(default_factory=dict)

    def key(self, item: _Owner) -> str:
        return "all users" if item.all_users else item.name.casefold()

    def target(self, item: _Owner) -> str:
        return "all users" if item.all_users else item.name

    async def read(self, client: AccessServerClient, item: _Owner) -> dict[str, Any]:
        if self.unassign and self.position is not None:
            raise ToolError(MSG_UNASSIGN_POSITION)
        self._rows, _ = await _rule_set(client, self.ruleset_id)
        name = self._rows[0].get("name") if self._rows else None
        shown = (
            f"rule set {self.ruleset_id}"
            if name is None
            else f"rule set {name} (id {self.ruleset_id})"
        )
        self.action = f"{'Unassign' if self.unassign else 'Assign'} {shown}"
        if item.all_users:
            label = _owner_label(DEFAULT_RECORD, None)
        else:
            if item.name == DEFAULT_RECORD:
                raise ToolError(MSG_DEFAULT_AS_OWNER)
            kind = await kind_of(client, item.name)
            if kind is None:
                raise _unknown_owner(item.name)
            label = f"{item.name} ({kind})"
        self._labels[item.sent] = label
        mine = _rows(await client.post("/access/rulesets/list", {"owner": item.sent}))
        self._others[item.sent] = [r for r in mine if r.get("id") != self.ruleset_id]
        return _holding(self.ruleset_id, mine)

    def plan(self, item: _Owner, before: dict[str, Any], own: Own) -> Plan:
        owner = clean(_owner_name(item.sent))
        has = before["position"]
        others = self._others[item.sent]
        if self.unassign:
            if has is None:
                raise ToolError(
                    f"Refused: {owner} does not have rule set {self.ruleset_id}."
                )
            keep = [row for row in self._rows if row.get("owner") not in self.taken]
            if not keep:
                raise ToolError(MSG_LAST_OWNER.format(id=self.ruleset_id))
            effects = [
                "owners that keep it: "
                + ", ".join(_state(self.ruleset_id, keep)["owners"])
            ]
            return Plan(
                PreviewItem(
                    self._labels[item.sent], {"position": (has, None)}, tuple(effects)
                ),
                auto_reason=AUTO_ACCESS,
            )
        if has is not None and self.position in (None, has):
            raise ToolError(
                f"Refused: {owner} already has rule set {self.ruleset_id} at position "
                f"{has}. Give another position to move it there."
            )
        if self.position is None:
            used = [r["position"] for r in others if isinstance(r.get("position"), int)]
            planned = max(used, default=0) + POSITION_STEP
        else:
            clash = next(
                (r for r in others if r.get("position") == self.position), None
            )
            if clash is not None:
                raise ToolError(
                    MSG_POSITION_TAKEN.format(
                        owner=owner,
                        name=clean(clash.get("name")),
                        id=clash.get("id"),
                        position=self.position,
                    )
                )
            planned = self.position
        self._planned[item.sent] = planned
        effects = []
        if others:
            effects.append(
                "its other rule sets: "
                + ", ".join(_holding(None, others)["other_rule_sets"])
            )
        return Plan(
            PreviewItem(
                self._labels[item.sent], {"position": (has, planned)}, tuple(effects)
            ),
            auto_reason=AUTO_ACCESS,
        )

    async def apply(
        self, client: AccessServerClient, item: _Owner, before: dict[str, Any]
    ) -> dict[str, Any]:
        if self.unassign:
            body: dict[str, Any] = {
                "delete": {item.sent: {"ruleset_ids": [self.ruleset_id]}}
            }
        else:
            position = self._planned[item.sent]
            body = {
                "add": {
                    item.sent: [{"ruleset_id": self.ruleset_id, "position": position}]
                }
            }
        await client.post("/access/user-rulesets/modify", body)
        return {}

    async def verify(self, client: AccessServerClient, item: _Owner) -> dict[str, Any]:
        mine = _rows(await client.post("/access/rulesets/list", {"owner": item.sent}))
        state = _holding(self.ruleset_id, mine)
        wanted = None if self.unassign else self._planned[item.sent]
        found = state["position"]
        if found != wanted:
            owner = _owner_name(item.sent)
            raise Partial(
                ["written"],
                f"Access Server shows {owner} without rule set {self.ruleset_id}"
                if found is None
                else f"Access Server shows {owner} with rule set {self.ruleset_id} "
                f"at position {found}",
            )
        return state


@dataclass(frozen=True)
class _RuleChange:
    ruleset_id: int
    add: tuple[RuleParam, ...]
    update: tuple[RuleUpdateParam, ...]
    delete: tuple[int, ...]


# (field of a rule, the word the approval question uses for it)
_RULE_FIELDS = (
    ("match_data", "domain"),
    ("match_type", "match_type"),
    ("action", "action"),
    ("position", "position"),
    ("comment", "comment"),
)


@dataclass
class _ModifyAccessRules:
    """The domain rules of one rule set: one /access/rules/modify request with the
    changed and new rules in `add` and the ids to remove in `delete`."""

    tool: str = "modify_access_rules"
    action: str = "Change rules of rule set"
    note: str = NOTE_DOMAIN_RULES
    needs_output_dir: bool = False
    _name: Any = None
    _rules: list[dict[str, Any]] = field(default_factory=list)
    _send: list[dict[str, Any]] = field(default_factory=list)
    _wanted: list[dict[str, Any]] = field(default_factory=list)

    def key(self, item: _RuleChange) -> str:
        return str(item.ruleset_id)

    def target(self, item: _RuleChange) -> str:
        return f"rule set {item.ruleset_id}"

    async def read(
        self, client: AccessServerClient, item: _RuleChange
    ) -> dict[str, Any]:
        self._rules = await _rules_of(client, item.ruleset_id)
        listed = _rows(await client.post("/access/rulesets/list", {}))
        self._name = next(
            (row.get("name") for row in listed if row.get("id") == item.ruleset_id),
            None,
        )
        return {"rules": _rule_labels(self._rules)}

    def plan(self, item: _RuleChange, before: dict[str, Any], own: Own) -> Plan:
        if not (item.add or item.update or item.delete):
            raise ToolError(MSG_NO_RULE_CHANGE)
        by_id = {rule.get("id"): rule for rule in self._rules}
        named = [update.id for update in item.update] + list(item.delete)
        for rule_id in named:
            if named.count(rule_id) > 1:
                raise ToolError(f"Refused: rule {rule_id} is named twice.")
            if rule_id not in by_id:
                raise ToolError(
                    f"Refused: rule set {item.ruleset_id} has no rule with id "
                    f"{rule_id}."
                )
        lines = [f"deletes {_rule_label(by_id[gone])}" for gone in item.delete]
        wanted = [rule for rule in self._rules if rule.get("id") not in item.delete]
        changed: list[dict[str, Any]] = []
        for update in item.update:
            old = by_id[update.id]
            if old.get("type") != RULE_TYPE:
                raise ToolError(
                    f"Refused: rule {update.id} is of type {clean(old.get('type'))}, "
                    "which as-mcp-server does not change; it can only delete it."
                )
            given = {
                "match_data": update.domain,
                "match_type": update.match_type,
                "action": update.action,
                "position": update.position,
                "comment": update.comment,
            }
            new = {**old, **{k: v for k, v in given.items() if v is not None}}
            diffs = [
                f"{word} {_value(old.get(key))} -> {_value(new.get(key))}"
                for key, word in _RULE_FIELDS
                if new.get(key) != old.get(key)
            ]
            if not diffs:
                raise ToolError(f"Refused: rule {update.id} already has these values.")
            lines.append(f"changes rule {update.id}: " + ", ".join(diffs))
            wanted = [new if rule.get("id") == update.id else rule for rule in wanted]
            changed.append(new)
        added: list[dict[str, Any]] = []
        for param in item.add:
            position = param.position
            if position is None:
                used = [
                    r["position"] for r in wanted if isinstance(r.get("position"), int)
                ]
                position = max(used, default=0) + POSITION_STEP
            rule = {
                "ruleset_id": item.ruleset_id,
                "type": RULE_TYPE,
                "match_type": param.match_type,
                "match_data": param.domain,
                "action": param.action,
                "position": position,
                "comment": param.comment,
            }
            wanted.append(rule)
            added.append(rule)
            lines.append(f"adds {_rule_label(rule)}")
        for rule in (*changed, *added):
            _check_place(rule, wanted)
        actions = {rule["action"] for rule in (*changed, *added)}
        effects = list(lines)
        self.note = NOTE_DOMAIN_RULES
        if "deny" in actions:
            effects.append(NOTE_DOMAIN_DENY)
            self.note = f"{NOTE_DOMAIN_RULES} {NOTE_DOMAIN_DENY}"
        if "bypass" in actions:
            effects.append(MSG_BYPASS)
        self._send = [*changed, *added]
        self._wanted = wanted
        shown = (
            f"rule set {item.ruleset_id}"
            if self._name is None
            else f"{self._name} (id {item.ruleset_id})"
        )
        return Plan(
            PreviewItem(
                shown,
                {"rules": (len(self._rules), len(wanted))},
                tuple(effects),
                order_after=tuple(_rule_labels(wanted)),
            ),
            auto_reason=AUTO_ACCESS,
        )

    async def apply(
        self, client: AccessServerClient, item: _RuleChange, before: dict[str, Any]
    ) -> dict[str, Any]:
        body: dict[str, Any] = {}
        if self._send:
            body["add"] = self._send
        if item.delete:
            body["delete"] = list(item.delete)
        answer = await client.post("/access/rules/modify", body)
        added = answer.get("added") if isinstance(answer, dict) else None
        return {"added": added if isinstance(added, list) else []}

    async def verify(
        self, client: AccessServerClient, item: _RuleChange
    ) -> dict[str, Any]:
        rules = await _rules_of(client, item.ruleset_id)
        if sorted(map(_comparable, rules)) != sorted(map(_comparable, self._wanted)):
            raise Partial(
                ["written"],
                "Access Server shows other rules: "
                + ("; ".join(_rule_labels(rules)) or "none"),
            )
        return {"rules": _rule_labels(rules)}


def _value(value: Any) -> Any:
    return '""' if value == "" else value


def _check_place(rule: dict[str, Any], rules: list[dict[str, Any]]) -> None:
    """A changed or new rule needs a position of its own and names no other rule
    of the set matches."""
    for other in rules:
        if other is rule:
            continue
        if other.get("position") == rule["position"]:
            raise ToolError(
                f"Refused: {_rule_label(other)} has position {rule['position']} "
                "too, and which of two rules at one position applies first is not "
                "known. Give another position."
            )
        if other.get("type") == RULE_TYPE and (
            other.get("match_type"),
            other.get("match_data"),
        ) == (rule["match_type"], rule["match_data"]):
            raise ToolError(
                f"Refused: {_rule_label(other)} matches the same names. Change it "
                "with update instead."
            )


async def _rules_of(
    client: AccessServerClient, ruleset_id: int
) -> list[dict[str, Any]]:
    try:
        answer = await client.post("/access/rules/list", {"ruleset_ids": [ruleset_id]})
    except ToolError as exc:
        if _gone(exc, ruleset_id):
            raise ToolError(MSG_NO_SUCH_RULESET.format(id=ruleset_id)) from exc
        raise
    rules = answer.get("rules") if isinstance(answer, dict) else None
    if not isinstance(rules, list):
        raise CannotCompute("the rules came back in an unknown shape")
    return [rule for rule in rules if isinstance(rule, dict)]


def _rule_label(rule: dict[str, Any]) -> str:
    domain, match = rule.get("match_data"), rule.get("match_type")
    if rule.get("type") == RULE_TYPE and match in PHRASES:
        kind, phrase = "", PHRASES[match].format(domain=domain)
    else:
        kind, phrase = f"{rule.get('type')} ", f"{match} {domain}"
    where = f"rule {rule['id']}" if "id" in rule else "new"
    position = rule.get("position")
    return f"{kind}{rule.get('action')} {phrase} (position {position}, {where})"


def _rule_labels(rules: list[dict[str, Any]]) -> list[str]:
    def order(rule: dict[str, Any]) -> tuple[int, int]:
        position, rule_id = rule.get("position"), rule.get("id")
        return (
            position if isinstance(position, int) else 0,
            rule_id if isinstance(rule_id, int) else 0,
        )

    return [_rule_label(rule) for rule in sorted(rules, key=order)]


def _comparable(rule: dict[str, Any]) -> str:
    keys = ("type", "match_type", "match_data", "action", "position", "comment")
    return json.dumps([rule.get(key) for key in keys])


def _holding(ruleset_id: int | None, rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Where one owner has the rule set, and its other rule sets."""
    here = next((row for row in rows if row.get("id") == ruleset_id), None)
    return {
        "position": None if here is None else here.get("position"),
        "other_rule_sets": [
            f"{row.get('name')} (id {row.get('id')}) at position {row.get('position')}"
            for row in rows
            if row is not here
        ],
    }


def _unknown_owner(name: str) -> ToolError:
    return ToolError(
        f"There is no user or group named {clean(name) or '""'} on this Access "
        "Server (names are case-sensitive)."
    )


def _check_text(item: _RuleSet) -> None:
    if len(item.name) > MAX_RULESET_NAME or not item.name.isprintable():
        raise ToolError(MSG_RULESET_NAME)
    comment = item.comment or ""
    if len(comment) > MAX_RULESET_COMMENT or not comment.isprintable():
        raise ToolError(MSG_RULESET_COMMENT)


def _gone(exc: ToolError, ruleset_id: int) -> bool:
    """Access Server answers an id it does not have with 400 "Non-existent ruleset:
    N" (measured on 3.1.0 and 3.2.4)."""
    return f"Non-existent ruleset: {ruleset_id}" in str(exc)


def _rows(answer: Any) -> list[dict[str, Any]]:
    rows = answer.get("rulesets") if isinstance(answer, dict) else None
    if not isinstance(rows, list):
        raise CannotCompute("the rule sets came back in an unknown shape")
    return [row for row in rows if isinstance(row, dict)]


async def _rule_set(
    client: AccessServerClient, ruleset_id: int
) -> tuple[list[dict[str, Any]], int]:
    """The rows of a rule set, one per owner, and its number of rules. Access Server
    lists only rule sets that have an owner; its rules show that one without an
    owner exists."""
    try:
        answer = await client.post("/access/rules/list", {"ruleset_ids": [ruleset_id]})
    except ToolError as exc:
        if _gone(exc, ruleset_id):
            raise ToolError(MSG_NO_SUCH_RULESET.format(id=ruleset_id)) from exc
        raise
    rules = answer.get("rules") if isinstance(answer, dict) else None
    if not isinstance(rules, list):
        raise CannotCompute("the rules came back in an unknown shape")
    listed = _rows(await client.post("/access/rulesets/list", {}))
    return [row for row in listed if row.get("id") == ruleset_id], len(rules)


def _owner_name(owner: Any) -> str:
    return "all users" if owner == DEFAULT_RECORD else str(owner)


def _owner_label(owner: Any, owner_type: Any) -> str:
    if owner == DEFAULT_RECORD:
        return "all users"
    return f"{owner} ({'group' if owner_type == 'group' else 'user'})"


def _state(ruleset_id: int, rows: list[dict[str, Any]]) -> dict[str, Any]:
    first = rows[0] if rows else {}
    return {
        "id": ruleset_id,
        "name": first.get("name"),
        "comment": first.get("comment"),
        "owners": [
            f"{_owner_label(row.get('owner'), row.get('owner_type'))} at position "
            f"{row.get('position')}"
            for row in rows
        ],
    }


def _unowned(ruleset_id: int) -> str:
    return (
        f"rule set {ruleset_id} has no owner, so Access Server does not list it; "
        "give it an owner with assign_access_ruleset or delete it with "
        "delete_access_rulesets"
    )


async def _default_via(client: AccessServerClient) -> str | None:
    answer = await client.post("/helper/status-overview", {"names": [PRIVATE_ACCESS]})
    items = (
        answer.get("configuration_items", {}).get("items", [])
        if isinstance(answer, dict)
        else []
    )
    for found in items if isinstance(items, list) else []:
        if isinstance(found, dict) and found.get("name") == PRIVATE_ACCESS:
            value = found.get("value")
            return value if isinstance(value, str) else None
    return None


def _placed(wanted: list[Item], new: Entry) -> str:
    index = wanted.index(new)
    if index + 1 < len(wanted):
        return f"adds {new.label()} in front of {wanted[index + 1].label()}"
    return f"adds {new.label()} at the end"


def _warnings(entries: list[Item]) -> list[str]:
    return [
        WARN_HIDDEN.format(entry=later.label(), earlier=earlier.label())
        for later, earlier in hidden(entries)
    ]


def register_access_write_tools(mcp: FastMCP, deps: WriteDeps) -> None:
    @mcp.tool(
        name="modify_access_list",
        description=(
            "Add or remove entries of the IPv4 access list of one user or group "
            "(what the owner may reach through the VPN). An entry allows or denies "
            "a network or a host, optionally only some services, by route or by "
            "nat. Access Server applies the first entry that matches, so a new "
            "entry is put right in front of the first wider entry it overlaps (a "
            "deny for one host goes in front of an allow for its network, and the "
            "other way round), else at the end; the approval question shows the "
            "order after the change. A deny here blocks the address; a domain "
            "rule with deny does not. The change applies only after a warm "
            "restart of Access Server (warm_restart, only when the user agrees). "
            "To replace an entry with its opposite, remove it and add the new one "
            "in the same call. Read the list first with list_access_lists. "
            "Refused in automatic approval mode. The item has 'warnings' for "
            "entries that have no effect." + RESULT_HELP
        ),
        annotations=DESTRUCTIVE,
        tags={"write"},
    )
    async def modify_access_list(
        ctx: Context,
        owner: Annotated[
            str,
            Field(
                min_length=1,
                max_length=128,
                description="Exact, case-sensitive name of one user or one group.",
            ),
        ],
        add: Annotated[
            list[EntryParam] | None,
            Field(max_length=MAX_ITEMS, description="Entries to add."),
        ] = None,
        remove: Annotated[
            list[EntryParam] | None,
            Field(
                max_length=MAX_ITEMS,
                description=(
                    "Entries to remove, as list_access_lists shows them: the same "
                    "subnet, allow, via and services. Every copy is removed."
                ),
            ),
        ] = None,
    ) -> Any:
        change = _Change(owner, tuple(add or ()), tuple(remove or ()))
        args = {
            "owner": owner,
            "add": [param.model_dump() for param in change.add],
            "remove": [param.model_dump() for param in change.remove],
        }
        return await run_write(ctx, deps, _ModifyAccessList(), [change], args)

    @mcp.tool(
        name="save_access_ruleset",
        description=(
            "Create a rule set of domain rules and give it to users, groups or all "
            "users, or change the name and comment of one. A rule set holds domain "
            "rules (add them with modify_access_rules). A user gets the rule sets "
            "of the user, of the user's group and of all users; of two rule sets "
            "of one owner the one with the lower position applies first. Without "
            "ruleset_id: a new rule set, which needs owners or all_users=true "
            "(Access Server does not list a rule set without an owner); position "
            "defaults to after the owner's last rule set. With ruleset_id: only "
            "name and comment change; to change who has it, use "
            "assign_access_ruleset. Domain rules apply from the next VPN connection "
            "of a user, without a restart. Refused in automatic approval mode. The "
            "item has 'id' of a new rule set." + RESULT_HELP
        ),
        annotations=WRITE,
        tags={"write"},
    )
    async def save_access_ruleset(
        ctx: Context,
        name: Annotated[
            str,
            Field(
                min_length=1,
                max_length=MAX_RULESET_NAME,
                description="Name of the rule set (a new one, or the new name).",
            ),
        ],
        comment: Annotated[
            str | None,
            Field(
                description=(
                    f"At most {MAX_RULESET_COMMENT} characters on one line. Omit to "
                    "keep the comment of an existing rule set (empty for a new one)."
                )
            ),
        ] = None,
        ruleset_id: Annotated[
            int | None,
            Field(
                ge=1,
                description=(
                    "Id of an existing rule set to rename (from "
                    "list_access_rulesets). Omit to create a new one."
                ),
            ),
        ] = None,
        owners: Annotated[
            list[Annotated[str, Field(min_length=1, max_length=128)]] | None,
            Field(
                max_length=MAX_ITEMS,
                description=(
                    "New rule set only: exact, case-sensitive names of the users and "
                    "groups that get it."
                ),
            ),
        ] = None,
        all_users: Annotated[
            bool,
            Field(description="New rule set only: true gives it to all users."),
        ] = False,
        position: Annotated[
            int | None,
            Field(
                ge=1,
                description=(
                    "New rule set only: its position at every owner; lower applies "
                    "first. Omit to put it after each owner's last rule set."
                ),
            ),
        ] = None,
    ) -> Any:
        item = _RuleSet(
            name, comment, ruleset_id, tuple(owners or ()), all_users, position
        )
        args = {
            "name": name,
            "comment": comment,
            "ruleset_id": ruleset_id,
            "owners": list(owners or ()),
            "all_users": all_users,
            "position": position,
        }
        action = "Create rule set" if ruleset_id is None else "Change rule set"
        return await run_write(ctx, deps, _SaveAccessRuleset(action), [item], args)

    @mcp.tool(
        name="delete_access_rulesets",
        description=(
            "Delete rule sets with all their domain rules; every owner loses them. "
            "The approval question names each rule set, its owners and how many "
            "rules it has. Cannot be undone. Refused in automatic approval mode."
            + RESULT_HELP
        ),
        annotations=DESTRUCTIVE,
        tags={"write"},
    )
    async def delete_access_rulesets(
        ctx: Context,
        ids: Annotated[
            list[Annotated[int, Field(ge=1)]],
            Field(
                max_length=MAX_ITEMS,
                description="Ids of the rule sets to delete (list_access_rulesets).",
            ),
        ],
    ) -> Any:
        return await run_write(
            ctx, deps, _DeleteAccessRulesets(), list(ids), {"ids": list(ids)}
        )

    @mcp.tool(
        name="assign_access_ruleset",
        description=(
            "Give an existing rule set to users, groups or all users, move it to "
            "another position at an owner that has it, or take it away "
            "(unassign=true). Of two rule sets of one owner the one with the lower "
            "position applies first; a new owner gets it after its last rule set "
            "unless position is given. Taking a rule set away from its last owner "
            "is refused: Access Server does not list a rule set without an owner; "
            "delete it with delete_access_rulesets instead. Domain rules apply "
            "from the next VPN connection of a user, without a restart. Refused in "
            "automatic approval mode." + RESULT_HELP
        ),
        annotations=WRITE,
        tags={"write"},
    )
    async def assign_access_ruleset(
        ctx: Context,
        ruleset_id: Annotated[
            int,
            Field(ge=1, description="Id of the rule set (from list_access_rulesets)."),
        ],
        owners: Annotated[
            list[Annotated[str, Field(min_length=1, max_length=128)]] | None,
            Field(
                max_length=MAX_ITEMS,
                description="Exact, case-sensitive names of users and groups.",
            ),
        ] = None,
        all_users: Annotated[
            bool, Field(description="true includes all users as one owner.")
        ] = False,
        unassign: Annotated[
            bool,
            Field(description="true takes the rule set away from these owners."),
        ] = False,
        position: Annotated[
            int | None,
            Field(
                ge=1,
                description=(
                    "Position at every owner; lower applies first. For an owner "
                    "that has the rule set, a new position moves it. Omit to put "
                    "it after each owner's last rule set."
                ),
            ),
        ] = None,
    ) -> Any:
        items = [_Owner(name) for name in owners or ()]
        if all_users:
            items.append(_Owner(DEFAULT_RECORD, all_users=True))
        taken = frozenset(item.sent for item in items) if unassign else frozenset()
        op = _AssignAccessRuleset(ruleset_id, unassign, position, taken)
        args = {
            "ruleset_id": ruleset_id,
            "owners": list(owners or ()),
            "all_users": all_users,
            "unassign": unassign,
            "position": position,
        }
        return await run_write(ctx, deps, op, items, args)

    @mcp.tool(
        name="modify_access_rules",
        description=(
            "Add, change or delete the domain rules of one rule set, in one "
            "request. A domain rule acts on names that a VPN client looks up "
            "through the DNS of the VPN: nat answers with an address that Access "
            "Server forwards to the host; route answers the same way but needs a "
            "route back from the host's network; deny refuses the name but does "
            "not block the address (use modify_access_list for that); bypass "
            "answers the real address and opens nothing. Of two rules of one rule "
            "set the lower position applies first; a new rule goes after the last "
            "one unless position is given. Give example.com with match_type "
            "subdomain, not *.example.com. To change a rule, give its id and only "
            "the fields to change. Rules apply from the next VPN connection of a "
            "user, without a restart. Refused in automatic approval mode. The item "
            "has 'added': the ids of the changed and then the new rules." + RESULT_HELP
        ),
        annotations=DESTRUCTIVE,
        tags={"write"},
    )
    async def modify_access_rules(
        ctx: Context,
        ruleset_id: Annotated[
            int,
            Field(ge=1, description="Id of the rule set (from list_access_rulesets)."),
        ],
        add: Annotated[
            list[RuleParam] | None,
            Field(max_length=MAX_ITEMS, description="New rules."),
        ] = None,
        update: Annotated[
            list[RuleUpdateParam] | None,
            Field(
                max_length=MAX_ITEMS,
                description="Changes of rules, by id; fields not given stay.",
            ),
        ] = None,
        delete: Annotated[
            list[Annotated[int, Field(ge=1)]] | None,
            Field(max_length=MAX_ITEMS, description="Ids of rules to delete."),
        ] = None,
    ) -> Any:
        change = _RuleChange(
            ruleset_id, tuple(add or ()), tuple(update or ()), tuple(delete or ())
        )
        args = {
            "ruleset_id": ruleset_id,
            "add": [param.model_dump() for param in change.add],
            "update": [param.model_dump() for param in change.update],
            "delete": list(change.delete),
        }
        return await run_write(ctx, deps, _ModifyAccessRules(), [change], args)
