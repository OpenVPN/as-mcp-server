"""Fixed texts of write mode. Agents relay them word for word, so they are frozen."""

from __future__ import annotations

MSG_CANCELLED = "Cancelled by the admin; nothing was changed."
MSG_NO_ELICITATION = (
    "Your AI app cannot show an approval prompt, so as-mcp-server did not make this "
    "change. Use an app that supports MCP elicitation, or set "
    "OPENVPN_AS_APPROVAL=auto in the MCP server settings to make changes without "
    "being asked."
)
MSG_CHANGED = (
    "Changed on the server since the preview; nothing was written. Run the request "
    "again."
)
MSG_LOCKOUT = (
    "Refused: this change would lock as-mcp-server out of its own admin account "
    "({name}). Make it in the Admin UI if it is really intended."
)
MSG_AUTO_LIMIT = (
    "Refused in automatic approval mode: {reason}. Repeat it in an app that shows "
    "the approval prompt, or in the Admin UI."
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
NOTE_GLOBAL_IP = (
    "Global IP/subnet rules are not visible through the API; check the Admin UI."
)
CLIENT_REASON = "Disconnected by your administrator."
DEFAULT_REASON = "Disconnected through as-mcp-server"
