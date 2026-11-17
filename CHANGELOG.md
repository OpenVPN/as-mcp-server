# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.2.0] - unreleased

Write mode: an administrator can let the agent change users, groups, connection profiles
and sessions. It is off by default, and every change is shown for approval first.

### Added
- Setting `OPENVPN_AS_WRITE_TOOLS` (default `false`): `true` registers twelve more tools.
  `OPENVPN_AS_APPROVAL` (`prompt` or `auto`) and `OPENVPN_AS_OUTPUT_DIR`. The first two are
  shown by `connection_info` and `as-mcp-server check`.
- The approval question: before a change is written the server shows the server, the action,
  every target with `before -> after` and the side effects, and asks through MCP elicitation.
  The answer is bound to the call and to the state that was shown; a changed state is read
  again and refused. An app that cannot ask gets a fixed message and nothing changes.
- Automatic approval (`OPENVPN_AS_APPROVAL=auto`) with hard limits: nobody becomes an
  administrator, MFA is not switched off, no authentication method is changed, autologin is
  not switched on, no autologin profile or link is created.
- The account the server signs in with cannot be deleted, blocked, demoted, moved to another
  group or switched to another authentication method, also not through its group.
- Connection profiles: `create_connection_profile`, `create_profile_download_link` and
  `delete_connection_profiles`. A profile or a link is saved to a file in the output folder
  (readable by its owner only) and the tool returns the path, never the content. A name that
  is not an existing user is refused (Access Server itself would issue a profile to a group
  name or an unknown name). Download links are limited to 7 days and 5 uses (`autologin`: 24
  hours and 5 uses).
- Sessions: `block_user` sets `deny` and then disconnects the user's running sessions,
  because Access Server does not end a running session when a user is blocked; it reports a
  session that is still connected. `disconnect_vpn_sessions` takes usernames or single
  sessions and does not block. The text shown to the VPN user is fixed.
- Users: `create_user` (a list; an optional generated password goes to a file, a password is
  never a parameter), `update_user` (one change for a list of users, a move to another
  group, `reset_to_inherited`; `deny=true` is refused in favour of `block_user`) and
  `delete_user` (profiles, the user, then the user's running sessions, which Access Server
  would leave connected).
- Groups: `create_group`, `update_group` and `delete_group`. Access Server refuses the VPN
  connections of the members of a new group until it is restarted; `create_group` says so
  before and after the change.
- A change that blocks a user without disconnecting them (a move into a blocked group, a
  reset of `deny`, a block set on a group) names the connected users in the approval text
  and in `warnings`.
- `create_support_report`, registered only in write mode: saves the Access Server support
  report to a file and returns the path and the size, never the text. It changes nothing and
  asks no approval; the request may take up to 5 minutes.
- List calls: up to 100 items with one approval, every item checked before anything is
  written, a result per item, nothing repeated after a timeout.
- An audit log, `<config dir>/audit.jsonl`: one line per item for every change the server
  tried, refused or saw cancelled.
- A 404 that names a missing object quotes Access Server instead of pointing at the server
  version.
- Two read tools, always on: `list_connection_profiles` (who holds which connection profile;
  never the profile file or its key; serials are strings of digits) and `list_access_lists`
  (IPv4 access lists of users and groups, with a note that the global IP/subnet rules and
  IPv6 access lists are not visible through the API).
- `docs/testing.md`: the manual checklist for the approval question in real apps.

### Changed
- The thirteen tools of 0.1.0 are unchanged, in both modes.
- An Access Server version that cannot be read is treated as below the supported minimum.
- FastMCP 4.1 or newer is required.
- Tested on Access Server 3.1.0 and 3.2.4.

### Fixed

- An invalid `OPENVPN_AS_*` variable (for example `OPENVPN_AS_WRITE_TOOLS=maybe` or
  `OPENVPN_AS_APPROVAL=never`) is reported as one line that names the variable and the
  allowed values, with exit code 1, instead of a Python traceback.
- `OPENVPN_AS_LOG_LEVEL` now sets the level of as-mcp-server's own lines only. Libraries
  log from WARNING up, so `DEBUG` no longer prints the HTTP library's lines with response
  headers, and `INFO` no longer prints full request URLs.

## [0.1.0] - 2026-10-05

First public release. Read-only: no tool changes anything on the server.

### Added
- Thirteen MCP tools for OpenVPN Access Server 3.1+ (Web API v0.2): `connection_info`,
  `login`, `get_status_overview`, `get_server_status`, `get_server_info`,
  `get_active_vpn_connections`, `get_log_reports`, `get_license_info`, `list_users`,
  `list_groups`, `get_default_user`, `list_access_rulesets`, `list_access_rules`. Every
  parameter carries a description in the MCP input schema (format, default behaviour and
  the API field it maps to).
- Command line: `as-mcp-server` (stdio server), `setup` (one-time credential storage,
  verified with a real login), `setup --clear`, `check`, `--version`.
- Credential storage: URL and username in `~/.config/as-mcp-server/profiles.toml`, password
  in the OS keyring (service `as-mcp-server`); `OPENVPN_AS_URL`, `OPENVPN_AS_USER` and
  `OPENVPN_AS_PASSWORD` override field by field.
- TLS options: verification on by default, `OPENVPN_AS_CA_CERT` for private CAs,
  `OPENVPN_AS_INSECURE=true` with a loud warning; `OPENVPN_AS_TIMEOUT`, `OPENVPN_AS_LOG_LEVEL`,
  `OPENVPN_AS_CONFIG_DIR`.
- Second sign-in steps: Access Server's own authenticator (a six-digit TOTP code through
  `login(totp_code)`) and challenges from a RADIUS, LDAP or PAM back end, whose prompt (for
  example `Enter your PIN`) is quoted to the agent word for word and answered as typed.
  `check` and `setup` prompt with the server's text. The answer goes to the challenge the
  server already issued, so a push-based back end is not triggered twice.
- Session renewal in the background: the client renews Access Server's short-lived tokens
  (10 minutes by default) before they expire, so an MFA account is asked for a code once per
  renewal window (4 hours by default). `connection_info.session` shows the state.
- Clear error texts: each one says what happened and what to do next. A SAML-bound account
  is refused with a message that no code can help, and the agent is told to stop.
- Tool calls are rate limited: 30 in a row, then 30 per minute, as the MCP specification
  requires. A refused call is a tool error that names the wait and tells the agent to stop
  repeating itself; initialize and the tool list are never refused.
- Server instructions that keep the agent on what the tools show: they tell it never to
  describe how to change Access Server (Admin UI steps, `sacli` or shell commands, file
  paths, config keys), also when the user asks how or when it would offer a change itself,
  and to link https://openvpn.net/as-docs/v3/ instead, since steps from memory are often for
  Access Server 2.x. Asked whether a user is locked out, the agent is told to call
  `get_log_reports` and `list_users` first and report what they show.
- `get_log_reports` explains that a record with the error `challenge` (or `Challenge`) is the
  first step of an MFA or RADIUS sign-in, not a failed login. A refused MFA code or challenge
  answer says that Access Server refuses a correct answer the same way once the account is
  locked, and points to the `LOCKOUT` log record instead of another attempt.
- The published package requires exactly the dependency versions it was tested with, so a
  new upstream release cannot reach users untested.

### Security
- Tool responses are redacted at any depth: `totp_secret`, `mfa_secret`,
  `pvt_google_auth_secret`, `password`, `auth_token`, `subkey`, and the `value` and
  `default_value` of configuration items whose key name looks like a secret (`*secret*`,
  `*password*`, `*passwd*`, `*bind_pw*`, `*token*`, `*_key`, `*.key`, also with a trailing
  version or index such as `acme.eab_hmac_key.2.9.0`), of `subscription.bundle` /
  `subscription.saved_state`, and of any item Access Server itself marks with a
  `redacted_value`.
- `challenge_context` is treated as a secret in every error text.
- `login` refuses a TOTP code that is not exactly six digits before any request is sent, so
  a mistyped code does not count as one of the five failed attempts that lock the account
  for 15 minutes.
- Client-chosen text in the log and in the connection list (username, certificate name,
  platform, version, proxied address) reaches the agent only when it looks like a plain
  value. The certificate name is checked under both spellings Access Server uses for it
  (`common_name`, `commonname`). Access Server logs a failed login with the username exactly as typed and without
  credentials, so anyone could otherwise put text in front of the model. Anything else is
  replaced by `{"withheld": true, "length", "flags", "fingerprint"}` and counted in
  `withheld_values`; error text loses control characters and is capped at 300 characters.
  The server instructions and the tool descriptions tell agents to report withheld values
  and never guess them.

### Known limitations
- No tool can tell whether a user is locked out right now: Access Server keeps that state
  internal. The tool descriptions say so, and agents are told to report the evidence
  instead.
- Accounts that must sign in through SAML are not supported: a browser-based login cannot
  be completed from an MCP server.
- The withheld-value check is a heuristic: a short plain-looking string, such as a
  three-word username, passes and reaches the model as data.
- An MCP `ping` is answered with "Method not found" (FastMCP 4.0.3).
