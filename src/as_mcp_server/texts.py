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
WARN_GROUP_RESTART = (
    "the group applies fully to the user only after a warm restart (warm_restart)"
)
NOTE_GROUP_RESTART = (
    "A user put into a group gets everything from the group only after a warm "
    "restart; ask the administrator whether to run warm_restart."
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
    "vpn.server.routing.private_network.0, .1, ... and "
    "vpn.server.routing.private_access with get_status_overview."
)
# Measured on 3.1.0 and 3.2.4: an IPv6 access list set on the server is not in the
# answer of /userprop/access/list, and the API refuses to write one.
NOTE_IPV6_ACCESS = "IPv6 access lists are not returned by the API."
NOTE_ACCESS_LISTS = f"{NOTE_GLOBAL_IP} {NOTE_IPV6_ACCESS}"
CLIENT_REASON = "Disconnected by your administrator."
DEFAULT_REASON = "Disconnected through as-mcp-server"
