"""The MCP tools. Every tool is a thin, typed wrapper over one Web API call.

Responses are the Access Server's own JSON passed through `redact()`; the only shaping
is in the request bodies, which are built from explicit parameters so an agent never
has to guess the API's filter grammar. Tools are registered in groups so a later
release can enable or disable groups by tag. Parameter descriptions condense the
Access Server Web API documentation and behaviour measured on real servers.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from as_mcp_server import __version__
from as_mcp_server.client import ClientHolder, redact
from as_mcp_server.config import describe
from as_mcp_server.untrusted import check_log_reports, check_vpn_status

READ = ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True
)
AUTH = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True
)
MINIMUM_VERSION = (3, 1)

SortDirection = Literal["asc", "desc"]
UserOrderBy = Literal["name", "admin", "autologin", "group", "mfa_status"]
GroupOrderBy = Literal[
    "name", "admin", "autologin", "auth_method", "mfa_enabled", "member_count"
]
LogOrderBy = Literal[
    "timestamp",
    "node",
    "username",
    "service",
    "duration",
    "active",
    "virtual_ipv4_address",
    "bytes_received",
    "bytes_sent",
    "error",
    "version",
    "gui_version",
    "platform",
    "protocol",
]
RuleType = Literal["domain_routing", "filter"]
PageSize = Annotated[
    int, Field(ge=1, le=1000, description="Records per page (1-1000).")
]
Offset = Annotated[
    int, Field(ge=0, description="Records to skip; page N starts at N*page_size.")
]
SortParam = Annotated[
    SortDirection,
    Field(
        description=(
            "Sort direction: asc (ascending) or desc (descending); the API's sort_by."
        )
    ),
]
LOG_SEARCH_FIELDS = [
    "username",
    "node",
    "service",
    "error",
    "platform",
    "version",
    "gui_version",
]


def register_tools(mcp: FastMCP, holder: ClientHolder) -> None:
    _register_diagnostics(mcp, holder)
    _register_status_tools(mcp, holder)
    _register_log_tools(mcp, holder)
    _register_directory_tools(mcp, holder)
    _register_access_tools(mcp, holder)


def _register_diagnostics(mcp: FastMCP, holder: ClientHolder) -> None:
    @mcp.tool(
        name="connection_info",
        description=(
            "Troubleshooting: which Access Server this MCP talks to, where the URL, "
            "user and password come from, TLS mode, session state and the server "
            "version. Never fails; problems are reported in the 'error' field."
        ),
        annotations=READ,
        tags={"diagnostics"},
    )
    async def connection_info() -> dict[str, Any]:
        info = describe(holder.settings, holder.profile)
        result: dict[str, Any] = {
            "url": info["url"],
            "username": info["username"],
            "config": {
                key: info[key]
                for key in (
                    "url_source",
                    "username_source",
                    "password_source",
                    "config_dir",
                    "profile",
                    "keyring_backend",
                    "profile_error",
                )
            },
            "tls": info["tls"],
            "session": {
                "authenticated": False,
                "expires_after": None,
                "renewable_until": None,
                "keep_alive": False,
                "challenge": None,
            },
            "server": None,
            "server_warning": None,
            "error": None,
            "mcp_version": __version__,
        }
        try:
            client = holder.get()
            server = redact(await client.get("/server/info"))
            result["url"], result["username"] = (
                client.config.url,
                client.config.username,
            )
            result["session"] = client.session_state()
            result["server"] = server
            version = str(server.get("version", "")) if isinstance(server, dict) else ""
            if below_minimum_version(version):
                result["server_warning"] = (
                    f"Access Server {version} is below the supported minimum "
                    f"{MINIMUM_VERSION[0]}.{MINIMUM_VERSION[1]}; Web API v0.2 "
                    "endpoints may be missing."
                )
        except ToolError as exc:
            result["error"] = str(exc)
            if holder.created:
                result["session"] = holder.get().session_state()
        return result

    @mcp.tool(
        name="login",
        description=(
            "Answer the server's second sign-in step. Only needed when another tool "
            "reported that Access Server asks for one: for its own authenticator "
            "prompt that is the current 6-digit MFA code; for a RADIUS, LDAP or PAM "
            "back end it is whatever the quoted prompt asks for (a PIN, a passcode). "
            "The session is then renewed in the background up to Access Server's "
            "renewal limit (4 hours by default); after that, or after the machine "
            "slept past the token's expiry, another tool asks again. Never pass a "
            "password."
        ),
        annotations=AUTH,
        tags={"auth"},
    )
    async def login(
        totp_code: Annotated[
            str,
            Field(
                description=(
                    "The user's answer to the server's prompt, sent as the response "
                    "to the pending challenge. For the authenticator prompt: the "
                    "current 6-digit code, valid for 30 seconds, usable once; spaces "
                    "are ignored and anything else is refused before it is sent. For "
                    "any other prompt: the text the prompt asks for, sent as typed "
                    "after trimming."
                )
            ),
        ],
    ) -> dict[str, Any]:
        return await holder.get().login(totp_code)


def _register_status_tools(mcp: FastMCP, holder: ClientHolder) -> None:
    @mcp.tool(
        name="get_status_overview",
        description=(
            "Consolidated health check in one call: server version and build, EULA "
            "status, DCO kernel module availability, and the current value of any "
            "configuration keys named in config_names (for example 'host.name', "
            "'vpn.server.daemon.enable')."
        ),
        annotations=READ,
        tags={"read"},
    )
    async def get_status_overview(
        config_names: Annotated[
            list[str] | None,
            Field(
                description=(
                    "Keys of configuration items to read from the active "
                    "configuration, for example 'host.name' or "
                    "'vpn.server.daemon.enable'; each comes back in "
                    "configuration_items with value, default_value and derived_from. "
                    "Omit for none."
                )
            ),
        ] = None,
    ) -> dict[str, Any]:
        body = {"names": list(config_names or [])}
        return redact(await holder.get().post("/helper/status-overview", body))

    @mcp.tool(
        name="get_server_status",
        description=(
            "Status of the Access Server's internal services (web, auth, api, "
            "daemons, ...) and authentication modules, plus the last restart time. "
            "Use it first when users report they cannot connect."
        ),
        annotations=READ,
        tags={"read"},
    )
    async def get_server_status() -> dict[str, Any]:
        return redact(await holder.get().get("/server/status"))

    @mcp.tool(
        name="get_server_info",
        description=(
            "Access Server version, build, web UI version, bundled client version, "
            "OS distribution, CPU architecture, core count and hostname."
        ),
        annotations=READ,
        tags={"read"},
    )
    async def get_server_info() -> dict[str, Any]:
        return redact(await holder.get().get("/server/info"))

    @mcp.tool(
        name="get_active_vpn_connections",
        description=(
            "Currently connected VPN clients (username, common name, real and "
            "virtual addresses, connected since, bytes in/out, cipher) and the "
            "OpenVPN daemons serving them. Always the full list; the API does not "
            "paginate this endpoint. A username or common name that is not a plain "
            'name is replaced by {"withheld": true, "length", "flags", "fingerprint"}, '
            "because the connecting client chose it; say it was withheld and never "
            "guess what it said."
        ),
        annotations=READ,
        tags={"read"},
    )
    async def get_active_vpn_connections() -> dict[str, Any]:
        return check_vpn_status(redact(await holder.get().get("/vpn/status")))

    @mcp.tool(
        name="get_license_info",
        description=(
            "Licensing status: licensing_type (subscription, fixed, aws, "
            "unlicensed), current and maximum concurrent connections, and "
            "subscription details such as state, cc_limit and next_update when a "
            "subscription is active."
        ),
        annotations=READ,
        tags={"read"},
    )
    async def get_license_info() -> dict[str, Any]:
        return redact(await holder.get().get("/license/info"))


def _register_log_tools(mcp: FastMCP, holder: ClientHolder) -> None:
    @mcp.tool(
        name="get_log_reports",
        description=(
            "Connection and authentication log records: who connected or failed to "
            "connect, when, from where, with which client, and any error text. "
            "since/until are relative durations like '30m', '24h', '7d', '15d 20m' "
            "(units s m h d w M y) counted back from now; errors_only keeps records "
            "with an error; search is a substring match over username, node, "
            "service, error, platform, version, gui_version. Returns 'records' "
            "and 'total'. Anyone can make a login attempt without credentials, so "
            "username, platform, version, gui_version and proxied_ip are client-chosen "
            "text: a value that is not a plain name, version or address is replaced "
            'by {"withheld": true, "length", "flags", "fingerprint"} (the same '
            "fingerprint means the same text) and 'withheld_values' counts them "
            "(absent when none were withheld); say how many were withheld and never "
            "guess what they said. A record whose error is 'challenge' or "
            "'Challenge' is the first step of an MFA or RADIUS sign-in, not a failed "
            "login. A record whose error starts with LOCKOUT marks the moment "
            "an account was locked after repeated failures (default 15 minutes); it "
            "does not show whether the lockout is still active, and its absence does "
            "not prove there was none."
        ),
        annotations=READ,
        tags={"read"},
    )
    async def get_log_reports(
        page_size: PageSize = 50,
        offset: Offset = 0,
        username: Annotated[
            str | None,
            Field(
                description=(
                    "Substring of the username that created the record (the API's "
                    "username filter, operation substring)."
                )
            ),
        ] = None,
        since: Annotated[
            str | None,
            Field(
                description=(
                    "Start of the time window as a relative duration counted back "
                    "from now, like '30m', '24h', '7d' or '15d 20m' (units s m h d w "
                    "M y). Sent as filters.timestamp.start_relative; omit for an "
                    "open start."
                )
            ),
        ] = None,
        until: Annotated[
            str | None,
            Field(
                description=(
                    "End of the time window as a relative duration counted back from "
                    "now, same format as since (for example '1m'). Sent as "
                    "filters.timestamp.end_relative; omit for an open end."
                )
            ),
        ] = None,
        errors_only: Annotated[
            bool,
            Field(
                description=(
                    "true keeps only records whose error field is not empty, i.e. "
                    "the error message of an authentication failure; false returns "
                    "all records."
                )
            ),
        ] = False,
        active_only: Annotated[
            bool,
            Field(
                description=(
                    "true keeps only records of sessions that are still active (the "
                    "API's boolean active filter)."
                )
            ),
        ] = False,
        search: Annotated[
            str | None,
            Field(
                description=(
                    "Substring searched at once in username, node, service, error, "
                    "platform, version and gui_version (the API's anywhere filter, "
                    "the only fields the server accepts there); combinable with the "
                    "other filters."
                )
            ),
        ] = None,
        order_by: Annotated[
            LogOrderBy,
            Field(
                description=(
                    "Record field to sort by (the API's order_by): timestamp is the "
                    "record time, duration is in seconds, bytes_sent and "
                    "bytes_received are byte counts."
                )
            ),
        ] = "timestamp",
        sort: SortParam = "desc",
    ) -> dict[str, Any]:
        filters: dict[str, Any] = {}
        if username:
            filters["username"] = {"operation": "substring", "value": username}
        if since or until:
            window: dict[str, str] = {}
            if since:
                window["start_relative"] = since
            if until:
                window["end_relative"] = until
            filters["timestamp"] = window
        if errors_only:
            filters["error"] = {"operation": "not_equal", "value": ""}
        if active_only:
            filters["active"] = {"value": True}
        if search:
            filters["anywhere"] = {"value": search, "fields": LOG_SEARCH_FIELDS}
        body: dict[str, Any] = {
            "page_size": page_size,
            "offset": offset,
            "order_by": order_by,
            "sort_by": sort,
        }
        if filters:
            body["filters"] = filters
        return check_log_reports(redact(await holder.get().post("/log/reports", body)))


def _register_directory_tools(mcp: FastMCP, holder: ClientHolder) -> None:
    @mcp.tool(
        name="list_users",
        description=(
            "Users defined on the Access Server (the special __DEFAULT__ user is "
            "excluded; use get_default_user for it). Each profile carries admin, "
            "autologin, deny, auth_method, group, mfa_status and other properties "
            "with inheritance metadata. Filters: name_contains (substring), group "
            "(exact group name), admins_only, autologin_only, usernames (exact list; "
            "unknown names are silently absent). Returns 'profiles' and 'total'. MFA "
            "secrets are redacted. Profiles carry no lockout state: deny, deny_web, "
            "totp_locked and mfa_status are permanent settings, and whether a user is "
            "locked out right now cannot be read through this server."
        ),
        annotations=READ,
        tags={"read"},
    )
    async def list_users(
        page_size: PageSize = 50,
        offset: Offset = 0,
        name_contains: Annotated[
            str | None,
            Field(
                description=(
                    "Substring of the user name (the API's name filter, operation "
                    "substring)."
                )
            ),
        ] = None,
        group: Annotated[
            str | None,
            Field(
                description=(
                    "Exact group name; only users whose group property equals it "
                    "(the API's group filter, operation equal)."
                )
            ),
        ] = None,
        admins_only: Annotated[
            bool,
            Field(
                description=(
                    "true returns only administrators (the API's boolean admin filter)."
                )
            ),
        ] = False,
        autologin_only: Annotated[
            bool,
            Field(
                description=(
                    "true returns only users with autologin enabled (the API's "
                    "boolean autologin filter)."
                )
            ),
        ] = False,
        usernames: Annotated[
            list[str] | None,
            Field(
                description=(
                    "Exact, case-sensitive usernames to fetch (the API's users list). "
                    "Names that do not exist are silently absent from the response; "
                    "keep the list short, the backend query has a size limit."
                )
            ),
        ] = None,
        order_by: Annotated[
            UserOrderBy,
            Field(
                description=(
                    "User attribute to sort by: name, admin, autologin, group or "
                    "mfa_status (the API's order_by)."
                )
            ),
        ] = "name",
        sort: SortParam = "asc",
    ) -> dict[str, Any]:
        filters: dict[str, Any] = {}
        if name_contains:
            filters["name"] = {"operation": "substring", "value": name_contains}
        if group:
            filters["group"] = {"operation": "equal", "value": group}
        if admins_only:
            filters["admin"] = {"value": True}
        if autologin_only:
            filters["autologin"] = {"value": True}
        body: dict[str, Any] = {
            "page_size": page_size,
            "offset": offset,
            "order_by": order_by,
            "sort_by": sort,
        }
        if filters:
            body["filters"] = filters
        if usernames:
            body["users"] = list(usernames)
        return redact(await holder.get().post("/users/list", body))

    @mcp.tool(
        name="list_groups",
        description=(
            "Groups defined on the Access Server with their properties and "
            "member_count; include_members=true adds the 'members' list. Filters: "
            "name_contains (substring), group_names (exact list). Returns 'profiles' "
            "and 'total'."
        ),
        annotations=READ,
        tags={"read"},
    )
    async def list_groups(
        page_size: PageSize = 50,
        offset: Offset = 0,
        name_contains: Annotated[
            str | None,
            Field(
                description=(
                    "Substring of the group name (the API's name filter, operation "
                    "substring)."
                )
            ),
        ] = None,
        include_members: Annotated[
            bool,
            Field(
                description=(
                    "true adds the members list to each group; false returns only "
                    "member_count (the API's enumerate_members)."
                )
            ),
        ] = False,
        group_names: Annotated[
            list[str] | None,
            Field(
                description=(
                    "Exact group names to fetch (the API's groups list). Names that "
                    "do not exist are silently absent from the response; keep the "
                    "list short, the backend query has a size limit."
                )
            ),
        ] = None,
        order_by: Annotated[
            GroupOrderBy,
            Field(
                description=(
                    "Group attribute to sort by: name, admin, autologin, "
                    "auth_method, mfa_enabled or member_count (the API's order_by)."
                )
            ),
        ] = "name",
        sort: SortParam = "asc",
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "page_size": page_size,
            "offset": offset,
            "order_by": order_by,
            "sort_by": sort,
            "enumerate_members": include_members,
        }
        if name_contains:
            body["filters"] = {
                "name": {"operation": "substring", "value": name_contains}
            }
        if group_names:
            body["groups"] = list(group_names)
        return redact(await holder.get().post("/groups/list", body))

    @mcp.tool(
        name="get_default_user",
        description=(
            "The __DEFAULT__ meta user: the property values every user and group "
            "inherits unless overridden (deny, deny_web, autologin, reroute_gw, "
            "def_deny, ...)."
        ),
        annotations=READ,
        tags={"read"},
    )
    async def get_default_user() -> dict[str, Any]:
        return redact(await holder.get().get("/users/defaultuser"))


def _register_access_tools(mcp: FastMCP, holder: ClientHolder) -> None:
    @mcp.tool(
        name="list_access_rulesets",
        description=(
            "Access-control rulesets assigned to an owner: a username, a group name, "
            "or '__DEFAULT__' for the global rulesets; omit owner to list every "
            "ruleset. Returns ids, names, positions and owners only; the actual "
            "rules come from list_access_rules(ruleset_ids=...). To answer 'what can "
            "user X reach', query the user, each of the user's groups (see "
            "list_users -> group) and '__DEFAULT__'."
        ),
        annotations=READ,
        tags={"read"},
    )
    async def list_access_rulesets(
        owner: Annotated[
            str | None,
            Field(
                description=(
                    "Assignee whose rulesets to list: a username, a group name, or "
                    "'__DEFAULT__' for the global rulesets. Omit to list every "
                    "ruleset."
                )
            ),
        ] = None,
        name_contains: Annotated[
            str | None,
            Field(
                description=(
                    "Substring of the ruleset name (the API's name filter, operation "
                    "substring)."
                )
            ),
        ] = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {}
        if owner:
            body["owner"] = owner
        if name_contains:
            body["filters"] = {
                "name": {"operation": "substring", "value": name_contains}
            }
        return redact(await holder.get().post("/access/rulesets/list", body))

    @mcp.tool(
        name="list_access_rules",
        description=(
            "The rules inside one or more rulesets: type (domain_routing or filter), "
            "match_type, match_data (domain, subnet, ...), action (route, nat, deny, "
            "bypass), position and comment. Filters: rule_type, match_data_contains "
            "(substring)."
        ),
        annotations=READ,
        tags={"read"},
    )
    async def list_access_rules(
        ruleset_ids: Annotated[
            list[int],
            Field(
                description=(
                    "IDs of the rulesets whose rules to list, at least one; take "
                    "them from list_access_rulesets."
                )
            ),
        ],
        rule_type: Annotated[
            RuleType | None,
            Field(
                description=(
                    "Keep only rules of this type: domain_routing or filter (the "
                    "API's type filter, operation equal)."
                )
            ),
        ] = None,
        match_data_contains: Annotated[
            str | None,
            Field(
                description=(
                    "Substring of the rule's match_data, for domain_routing rules "
                    "part of a domain name (the API's match_data filter, operation "
                    "substring)."
                )
            ),
        ] = None,
    ) -> dict[str, Any]:
        if not ruleset_ids:
            raise ToolError(
                "ruleset_ids must contain at least one id; "
                "get them from list_access_rulesets."
            )
        body: dict[str, Any] = {"ruleset_ids": list(ruleset_ids)}
        filters: dict[str, Any] = {}
        if rule_type:
            filters["type"] = {"operation": "equal", "value": rule_type}
        if match_data_contains:
            filters["match_data"] = {
                "operation": "substring",
                "value": match_data_contains,
            }
        if filters:
            body["filters"] = filters
        return redact(await holder.get().post("/access/rules/list", body))


def below_minimum_version(version: str) -> bool:
    try:
        major, minor = (int(part) for part in version.split(".")[:2])
    except ValueError:
        return False
    return (major, minor) < MINIMUM_VERSION
