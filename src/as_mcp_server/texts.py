"""Fixed texts of write mode. Agents relay them word for word, so they are frozen."""

from __future__ import annotations

MSG_CANCELLED = "Cancelled by the admin; nothing was changed."
MSG_NO_ELICITATION = (
    "Your AI app cannot show an approval prompt, so as-mcp-server did not make this "
    "change. Use an app that supports MCP elicitation, or set "
    "OPENVPN_AS_APPROVAL=auto in the MCP server settings to make changes without "
    "being asked."
)
MSG_CHANGED = "Changed on the server since the preview; nothing was written."
MSG_LATE_ANSWER = (
    "Refused: the answer to the approval question of {tool} came more than 10 minutes "
    "after the question, or does not belong to it. Nothing was changed. Call {tool} "
    "again to be asked anew."
)
MSG_LOCKOUT = (
    "Refused: this change would lock as-mcp-server out of its own admin account "
    "({name}). Make it in the Admin UI if it is really intended."
)
MSG_AUTO_LIMIT = (
    "Refused in automatic approval mode: {reason}. Repeat it in an app that shows "
    "the approval prompt, or in the Admin UI."
)
MSG_RESTART_NEEDS_PROMPT = (
    "Refused: a warm restart always needs the administrator's approval, and your AI "
    "app cannot show an approval prompt. Nothing was restarted. Use an app that "
    "supports MCP elicitation."
)
NOTE_RESTARTED = (
    "Access Server was restarted (warm). Connected VPN clients may have been "
    "disconnected and reconnect by themselves. Groups created before the restart "
    "work now."
)
WARN_FRESH_GROUP = (
    "group {group} was created after the last restart: {name} cannot connect "
    "until a warm restart (warm_restart)"
)
MSG_AUTO_FRESH_GROUP = (
    "Refused in automatic approval mode: group {group} was created after the last "
    "restart, and {name} could not connect. Run warm_restart first, then repeat."
)
WARN_RECONNECT = (
    "{name} is connected and keeps the old access until the session ends; "
    "disconnect_vpn_sessions ends it"
)
NOTE_GROUP_MOVE = (
    "A user moved to another group gets the values of that group at the next VPN "
    "connection; a running session keeps the old ones until it ends. The members "
    "of a group created since the last restart cannot connect until warm_restart."
)
WARN_OWN_MFA = (
    "the account as-mcp-server signs in with ({name}) will need an MFA code at the "
    "next sign-in."
)
MSG_UNTESTED = "Access Server {server} is not on the tested list of as-mcp-server {mcp}"
MSG_USE_BLOCK = (
    "Refused: use block_user to block a user; it also disconnects the user's sessions."
)
MSG_NOT_DISCONNECTED = (
    "{name} is blocked but is not disconnected by this change; use "
    "disconnect_vpn_sessions."
)
MSG_ONE_TARGET = "Give exactly one of {a} or {b}."
# The AS team (AS-6617): the global subnet rules are configuration keys.
NOTE_GLOBAL_IP = (
    "Global IP/subnet rules are server settings, not access lists: read "
    "vpn.server.routing.private_network.0, .1, ..., "
    "vpn.server.routing.routed_subnets.0, .1, ... and "
    "vpn.server.routing.private_access with get_status_overview."
)
# Measured on 3.1.0 and 3.2.4: an IPv6 access list set on the server is not in the
# answer of /userprop/access/list, and the API refuses to write one.
NOTE_IPV6_ACCESS = "IPv6 access lists are not returned by the API."
NOTE_ACCESS_LISTS = f"{NOTE_GLOBAL_IP} {NOTE_IPV6_ACCESS}"
CLIENT_REASON = "Disconnected by your administrator."
DEFAULT_REASON = "Disconnected through as-mcp-server"
MSG_USE_BLOCK_GROUP = (
    "Refused: use block_group to block a group; it also disconnects the members' "
    "sessions."
)
AUTO_ACCESS = (
    "access rules and access lists are changed only after the approval question"
)
AUTO_PASSWORD = "a password is reset only after the approval question"
AUTO_MFA = "MFA is reset only after the approval question"
MSG_UNTESTED_REFUSED = (
    "Refused: Access Server {server} is not on the tested list of as-mcp-server "
    "{mcp}, and access lists are changed only on tested versions. Make the change in "
    "the Admin UI."
)
NOTE_ACCESS_LIST_RESTART = (
    "Saved. Access Server applies a changed access list only after a warm restart, "
    "which may briefly reconnect some users. Until then the old list applies. Ask "
    "the administrator before calling warm_restart."
)
NOTE_DOMAIN_RULES = (
    "Saved. Domain rules apply without a restart, from the next connection of a user. "
    "They act on names that the device looks up through the DNS of the VPN; the "
    "address of the host itself is not opened."
)
NOTE_DOMAIN_DENY = (
    "A domain rule with the action deny acts on the name only: it does not block the "
    "address of the host, and an access list that allows the address still lets the "
    "traffic through. To block an address, change the access list."
)
MSG_LAST_OWNER = (
    "Refused: rule set {id} would have no owner left, and Access Server does not list "
    "such a rule set. Use delete_access_rulesets to remove it."
)
MSG_NO_SUCH_RULESET = "Refused: there is no rule set with id {id}."
MSG_DUPLICATE_ENTRY = "Refused: the access list of {owner} already has {entry}."
MSG_CONFLICT_ENTRY = (
    "Refused: the access list of {owner} already has {entry} with the opposite "
    "action. Remove it in the same call if the new entry should replace it."
)
MSG_NOT_WRITABLE = (
    "Refused: the access list of {owner} holds {entry}, which the Web API cannot "
    "write back, and this change would have to rewrite it. Make the change in the "
    "Admin UI."
)
MSG_NO_SUCH_ENTRY = "Refused: the access list of {owner} has no entry {entry}."
WARN_HIDDEN = (
    "{entry} has no effect: {earlier} comes first and matches the same traffic."
)
MSG_NO_ACCESS_CHANGE = (
    "Refused: nothing to change. Give at least one entry to add or to remove."
)
MSG_GROUP_AND_REMOVE = "Refused: give group or remove_from_group, not both."
MSG_IN_NO_GROUP = "Refused: {name} is in no group."
MSG_NO_MFA_TO_RESET = (
    "Refused: {name} has not set up MFA, so there is nothing to reset."
)
MSG_MFA_NOT_ALLOWED = (
    "Refused: {name} signs in with {method}, which has no MFA of Access Server to "
    "reset."
)
# Measured on 3.1.0 and 3.2.4 (dev/README.md).
NOTE_PASSWORD_RESET = (
    "The old password stops working at once; a VPN session of the user stays connected."
)
NOTE_MFA_RESET = "The user sets up MFA again at the next sign-in."
