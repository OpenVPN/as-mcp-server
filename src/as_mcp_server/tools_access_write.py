"""Write-mode tools for access control: `modify_access_list`.

Measured on 3.1.0 and 3.2.4: the first entry of an access list that matches wins;
one /userprop/access/set request with items_remove and items_append reorders a
list (the removal first, every copy of an item); a changed access list applies
only after a warm restart.
"""

from __future__ import annotations

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
from as_mcp_server.client import AccessServerClient
from as_mcp_server.effective import DEFAULT_RECORD
from as_mcp_server.preview import PreviewItem, clean
from as_mcp_server.texts import (
    AUTO_ACCESS,
    MSG_NO_ACCESS_CHANGE,
    NOTE_ACCESS_LIST_RESTART,
    NOTE_GLOBAL_IP,
    WARN_HIDDEN,
)
from as_mcp_server.writes import (
    DESTRUCTIVE,
    MAX_ITEMS,
    RESULT_HELP,
    Own,
    Partial,
    Plan,
    WriteDeps,
    kind_of,
    run_write,
)

TOOLS = ("modify_access_list",)
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
            raise ToolError(
                f"There is no user or group named {clean(item.owner) or '""'} on "
                "this Access Server (names are case-sensitive)."
            )
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
