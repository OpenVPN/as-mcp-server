# as-mcp-server

A local [MCP](https://modelcontextprotocol.io) server that lets your own AI agent (Claude Code,
Codex, Cursor, VS Code, OpenCode, Claude Desktop, ...) look at your **OpenVPN Access Server**
through its Web API. By default it is **read-only**: it answers questions such as "is the VPN
healthy", "who is connected", "who failed to log in today", "what can user X reach" and never
changes anything on the server. Since 0.2.0 an administrator can switch on **write mode**
(users, groups, connection profiles, block and disconnect), where every change is shown for
approval first; see [Write mode](#write-mode).

It runs on your machine, is started by your agent, and talks to Access Server with your own
admin credentials. Nothing is hosted by anyone else.

Copyright (c) 2026 OpenVPN Inc. Licensed under the MIT License, see `LICENSE`.

## Requirements

- OpenVPN Access Server **3.1 or newer** (Web API v0.2). Tested on 3.1.0 and 3.2.4.
- An **admin** account on that server. Use a dedicated one for the agent.
- [uv](https://docs.astral.sh/uv/) on your machine. It downloads Python if needed; nothing
  else has to be installed.

## Install (about two minutes)

These steps are written so you can hand them to your agent ("set this up for me") or follow
them yourself.

1. Install uv.
   - macOS / Linux: `curl -LsSf https://astral.sh/uv/install.sh | sh`
   - Windows (PowerShell): `powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"`
   - or `brew install uv`, `winget install astral-sh.uv`, `pipx install uv`.
2. Store the connection once. This asks for the server URL, the admin username and the
   password (typed hidden, never shown to the agent), checks them against the server, then
   saves URL and username to `~/.config/as-mcp-server/profiles.toml` and the password in your
   OS keyring (macOS Keychain, Windows Credential Manager, Linux Secret Service):

       uvx --python 3.13 as-mcp-server setup

   If the account needs a second sign-in step you are asked for it as well, with the server's
   own prompt (the authenticator code, or for example a PIN from a RADIUS back end).
3. Register the server with your agent: run its command from the table in
   [Agent setup](#agent-setup), or add the entry to its configuration file. There is no
   secret in this configuration.
4. Ask the agent something: "Is my VPN healthy?" It will call `get_status_overview`.

Pin a version if you want upgrades to be explicit: `uvx --python 3.13 as-mcp-server@0.2.0`. `uvx` keeps
using the version it first cached until you pass `@latest` or run `uv cache clean`.

Every command names the Python version (`--python 3.13`); uv downloads that Python itself if
it is missing. Without the flag uv picks the newest Python it can find, and a release keeps
the exact dependency versions it was tested with, some of which have no ready-made build for
a Python that came out later: the install then needs a C and Rust compiler, or fails. Python
3.12 works as well.

### Agent setup

| Agent | Command | Configuration file |
| --- | --- | --- |
| Claude Code | `claude mcp add openvpn-as -- uvx --python 3.13 as-mcp-server` | `~/.claude.json` (add `--scope user` to use it in every project) |
| Codex CLI | `codex mcp add openvpn-as -- uvx --python 3.13 as-mcp-server` | `~/.codex/config.toml` |
| Gemini CLI | `gemini mcp add -s user openvpn-as uvx -- --python 3.13 as-mcp-server` (the `--` comes after `uvx`) | `~/.gemini/settings.json` |
| OpenCode | `opencode mcp add openvpn-as -- uvx --python 3.13 as-mcp-server` | `opencode.json` in the folder where you ran the command (that folder only); `~/.config/opencode/opencode.json` (or `.jsonc`) for every folder |
| VS Code | `code --add-mcp '{"name":"openvpn-as","command":"uvx","args":["--python","3.13","as-mcp-server"]}'` | the user profile's `mcp.json` ("MCP: Open User Configuration"), or `.vscode/mcp.json` in a project |
| Cursor | - | `~/.cursor/mcp.json`, or `.cursor/mcp.json` in a project |
| Claude Desktop | - | macOS `~/Library/Application Support/Claude/claude_desktop_config.json`, Windows `%APPDATA%\Claude\claude_desktop_config.json` (Settings, Developer, Edit Config) |

In Windows PowerShell type `claude.cmd` instead of `claude`: PowerShell drops the `--` when it
runs the `claude.ps1` wrapper, and the command then fails.

The entry has a different shape per agent. Claude Desktop, Cursor and Gemini CLI (and Claude
Code's project file `.mcp.json`):

    {
      "mcpServers": {
        "openvpn-as": { "command": "uvx", "args": ["--python", "3.13", "as-mcp-server"] }
      }
    }

VS Code:

    {
      "servers": {
        "openvpn-as": { "type": "stdio", "command": "uvx", "args": ["--python", "3.13", "as-mcp-server"] }
      }
    }

Codex CLI:

    [mcp_servers.openvpn-as]
    command = "uvx"
    args = ["--python", "3.13", "as-mcp-server"]

OpenCode 1.x (the command is one array, the server sits directly under `mcp`):

    {
      "$schema": "https://opencode.ai/config.json",
      "mcp": {
        "openvpn-as": { "type": "local", "command": ["uvx", "--python", "3.13", "as-mcp-server"] }
      }
    }

OpenCode 2 (the server sits under `mcp.servers`):

    {
      "mcp": {
        "servers": {
          "openvpn-as": { "type": "local", "command": ["uvx", "--python", "3.13", "as-mcp-server"] }
        }
      }
    }

Both versions have the `opencode mcp add openvpn-as -- uvx --python 3.13 as-mcp-server` command; 1.x writes
the first form.
OpenCode reads two files: `opencode.json` in a project folder, which applies only when
OpenCode is started from that folder, and `~/.config/opencode/opencode.json`, which applies
everywhere. With OpenCode 2.3.2 the command above wrote the project file. If the server is
missing in another folder, move the entry to the file in `~/.config/opencode`. The project
file is created readable by other users of the machine and is easy to commit by accident, so
do not pass the password with `--env` there: run `setup` once, which keeps it in the system
keyring.

### Alternative: environment variables (headless Linux, CI, or by preference)

Skip `setup` and give the agent the settings as environment variables of the server entry.
With a command, add one flag per variable: `--env KEY=value` for Codex CLI and OpenCode, `-e
KEY=value` for Gemini CLI and Claude Code. Claude Code reads every word after `-e` as another
variable, so put the server name first:

    claude mcp add openvpn-as -e OPENVPN_AS_URL=https://vpn.example.com:943 \
      -e OPENVPN_AS_USER=mcp-admin -e OPENVPN_AS_PASSWORD=... -- uvx --python 3.13 as-mcp-server

In a configuration file the variables go into `env` next to `command` (Claude Desktop, Cursor,
Gemini CLI, VS Code, Claude Code), into `environment` for OpenCode, and into a
`[mcp_servers.openvpn-as.env]` table for Codex CLI:

    {
      "mcpServers": {
        "openvpn-as": {
          "command": "uvx",
          "args": ["--python", "3.13", "as-mcp-server"],
          "env": {
            "OPENVPN_AS_URL": "https://vpn.example.com:943",
            "OPENVPN_AS_USER": "mcp-admin",
            "OPENVPN_AS_PASSWORD": "..."
          }
        }
      }
    }

The password then lives in plain text in that file, like any API key in an MCP configuration.
Environment variables override the stored profile field by field.

### Check it works

    uvx --python 3.13 as-mcp-server check

prints the URL, user, where each value came from, TLS mode and the server version. Inside a
conversation the equivalent is the `connection_info` tool, which never fails and reports any
problem in its `error` field.

## Tools

With default settings all tools are read-only except `login`, which only creates a session.
The tools that change the server are listed under [Write mode](#write-mode).

| Tool | What it answers | Parameters |
| --- | --- | --- |
| `connection_info` | Which server, which user, TLS mode, session, server version; problems as text | - |
| `login` | Answer the second sign-in step: the authenticator code or the back end's prompt | `totp_code` |
| `get_status_overview` | One-call health check: version, EULA, DCO, chosen config values | `config_names` (optional) |
| `get_server_status` | Internal services and auth modules, last restart | - |
| `get_server_info` | Version, build, OS, architecture, hostname | - |
| `get_active_vpn_connections` | Connected clients and daemons | - |
| `get_log_reports` | Connection / authentication log with filters | `page_size`, `offset`, `username`, `since`, `until`, `errors_only`, `active_only`, `search`, `order_by`, `sort` |
| `get_license_info` | License type, concurrent connections, subscription state | - |
| `list_users` | Users and their properties (MFA secrets redacted) | `page_size`, `offset`, `name_contains`, `group`, `admins_only`, `autologin_only`, `usernames`, `order_by`, `sort` |
| `list_groups` | Groups, member counts or members | `page_size`, `offset`, `name_contains`, `include_members`, `group_names`, `order_by`, `sort` |
| `get_default_user` | The `__DEFAULT__` profile everyone inherits from | - |
| `list_access_rulesets` | Rulesets assigned to a user, a group or `__DEFAULT__` | `owner`, `name_contains` |
| `list_access_rules` | The rules (destination, action) inside rulesets | `ruleset_ids`, `rule_type`, `match_data_contains` |
| `list_connection_profiles` | Who holds which connection profile: serial, type, validity, last use (never the profile or its key) | `username`, `autologin_only`, `page_size`, `offset` |
| `list_access_lists` | IPv4 subnet access lists of users and groups | `usernames`, `group_names` |

Responses are the Access Server API's own JSON. `since`/`until` are relative durations such
as `30m`, `24h`, `7d`, `15d 20m`. "What can user X reach": rulesets for the user, for each of
the user's groups, and for `__DEFAULT__`, then `list_access_rules` with the collected ids,
then `list_access_lists` for the IPv4 subnet rules. Global IP/subnet rules are server
settings, not access lists: `get_status_overview` reads them when you name the keys
`vpn.server.routing.private_network.0`, `.1`, ..., `vpn.server.routing.routed_subnets.0`,
`.1`, ... and `vpn.server.routing.private_access`.
IPv6 access lists are not returned by the API; check them in the Admin UI. Profile serials
are strings of digits (they are too large for a JSON number).

## Write mode

Off by default. With `OPENVPN_AS_WRITE_TOOLS=true` the server registers thirteen more tools:

| Tool | What it does | Parameters |
| --- | --- | --- |
| `create_connection_profile` | New profile per user, saved to a local file | `usernames`, `profile_type`, `tls_crypt_v2`, `comment` |
| `create_profile_download_link` | Download link per user (called Token URL in Access Server; 1 to 5 uses), saved to a local file | `usernames`, `profile_type`, `lifetime_seconds`, `usages` |
| `delete_connection_profiles` | Delete profiles by serial, or every profile of one user | `serials` or `username` |
| `block_user` | Set `deny`, disconnect the user's sessions, check that none is left | `usernames` |
| `disconnect_vpn_sessions` | Disconnect every session of users, or single sessions; does not block | `usernames` or `sessions`, `reason` |
| `create_support_report` | Save the Access Server support report to a local file (a read; no approval) | - |
| `create_user` | Create users; an optional generated password goes to a local file | `users`: `username`, `group`, `admin`, `auth_method`, `deny`, `generate_password` |
| `update_user` | One change for a list of users; move to a group; reset fields to the inherited value | `usernames`, `deny`, `deny_web`, `admin`, `autologin`, `auth_method`, `group`, `totp`, `allow_password_change`, `allow_generate_profiles`, `reroute_gw`, `reset_to_inherited` |
| `delete_user` | Delete the user's profiles, the user, then disconnect the user's sessions | `usernames` |
| `create_group` | Create a group | `name` and the group fields |
| `update_group` | Change one group | `name`, the group fields, `reset_to_inherited` |
| `delete_group` | Delete one group; its members stay as users | `name` |
| `warm_restart` | Warm restart of Access Server; always asks for approval | - |

How to switch it on, for Claude Code:

    claude mcp add openvpn-as -e OPENVPN_AS_WRITE_TOOLS=true -- uvx --python 3.13 as-mcp-server

(or add `"OPENVPN_AS_WRITE_TOOLS": "true"` to the `env` block of your agent's MCP configuration).
`uvx --python 3.13 as-mcp-server check` and the `connection_info` tool show whether write mode is on.

**Approval.** Before anything is written, the server shows you what will change (the server,
the action, every target with `field: before -> after`, and the side effects) and asks for a
yes. This uses MCP elicitation, so the question is asked by your AI app, not by the model; the
model cannot answer it. Decline or cancel and nothing changes. The state is read again after
your yes; if someone changed it in the meantime the write is refused with "Changed on the
server since the preview; nothing was written." and the agent stops; ask again if you still
want the change. An app that cannot show the question gets this answer and nothing changes:
"Your AI app cannot show an approval prompt, so as-mcp-server did not make this change. Use
an app that supports MCP elicitation, or set OPENVPN_AS_APPROVAL=auto in the MCP server
settings to make changes without being asked."
With an app that speaks the MCP protocol of 2026-07-28 a question stays open for 10 minutes.
A later answer is refused ("... came more than 10 minutes after the question, or does not
belong to it. Nothing was changed. ..."), nothing changes and the audit log gets a
`refused_no_approval` line; ask for the change again.

**What your app shows of the question.** Apps differ, so the first three lines carry the
most: the server, the action with the number of targets and the first three names, and a
`Total:` line (for example `Total: deletes 3 connection profiles, disconnects 1 active
session, cannot be undone, 1 warning`). For `update_user` and `update_group` the `Total:`
line starts with the change itself: `Total: admin false -> true, autologin false -> true`
for one target, `Total: changes admin, autologin for 3 users` for several. The full list of
values (`field: before -> after`) comes after these lines. As tested for this release:

- Claude Code 2.1.325 shows only the first three lines ("... (+N more lines)") and has no
  key to open the rest.
- Codex 0.169.0 shows as many lines as fit the height of the terminal window.
- Claude Desktop 5.11492.5 does not show the question at all, so it can write only with
  `OPENVPN_AS_APPROVAL=auto`.

Claude Desktop also stops waiting for a tool after about 80 seconds. `create_support_report`
can take longer (the server waits up to 5 minutes for the report): the chat then shows an
error or no result, but the report is still saved. Look for the file in the output folder.

What the agent says afterwards is the model's own wording. In one test run an agent
reported a cancelled change as done; `audit.jsonl` (below) says what really happened.

**Automatic approval.** `OPENVPN_AS_APPROVAL=auto` makes changes without asking. Use it only
where you trust the agent and its inputs. Even then the server never: gives administrator
rights, switches MFA off, changes an authentication method, creates a user with an
authentication method other than the one it would inherit, switches autologin on, creates an
autologin profile or link, switches MFA on for the account it signs in with itself, or makes
a change whose result it cannot compute. These are
refused with the reason; make them in an app that shows the approval prompt. It also refuses
to put a user into a group that was created after the last restart, because that user could
not connect; restart first, then repeat. Deleting a user
is done without a question. Deleting a group is done without a question too, unless a member
would lose MFA, a block or its authentication method with the group; then it is refused.

**Restart.** No tool restarts Access Server by itself. One change needs a warm restart: a
new group. Until the restart Access Server refuses the VPN connections of its members
("User authentication failed"). `create_group` says so, and a user put into such a group gets
the line "group ... was created after the last restart: ... cannot connect until a warm
restart". The server remembers the groups it created in `<config dir>/fresh_groups.json`, so
this also works in a later session; a restart made anywhere, also in the Admin UI, clears it.
A group created in the Admin UI is not known to the server and gets no such line.
A group that is deleted and created again under the same name works without a restart, as
long as the name was there at the last restart; `create_group` says so for a group that was
deleted through this server, and warns as for a new group when it was deleted elsewhere.
Until the next restart Access Server keeps the access rules of the deleted group in its
firewall (measured on 3.1.0 and 3.2.4), and `create_group` says that too; the other values
of the new group apply at the next VPN connection.
A user moved to another group gets it at the next VPN connection. A running session keeps
the access of the old group, and a restart does not move it to the new group (measured on
3.1.0 and 3.2.4); the tool says so when the user is connected, and `disconnect_vpn_sessions`
ends the session. This is about a change of group only: after other changes, such as access
rules or split-tunnel routes, a warm restart can still make a connected user reconnect.
`warm_restart` does the restart when you ask for it. It asks for your approval every time,
also with
`OPENVPN_AS_APPROVAL=auto`, and the question says how many VPN clients are connected: a warm
restart can disconnect them, and they have to reconnect. An app that cannot show the
question (Claude Desktop) cannot restart.

**The agent's own account is protected in every mode.** A change that would block, delete or
demote the account as-mcp-server signs in with, move it to another group, change its
authentication method or delete its group is refused, also when it would arrive through the
account's group. Switching MFA on for that account is not a lockout, but the next sign-in
then needs a code from a person: the approval question says so, and automatic mode refuses
it. The account is recognised without looking at letter case: signed in as `openvpn`, a
user named `OpenVPN` is protected too and has to be changed in the Admin UI. With LDAP or
RADIUS sign-in and the case-sensitive option off, Access Server treats such names as one user.

**Lists.** A tool that takes a list handles up to 100 items in one call with one approval.
Every item is checked before anything is written; one bad item refuses the whole call. When
you approve, every item is read again: if one of them changed on the server while the
question was open, nothing is written and every item is `refused_changed`. After that the
items are written in order; at the first item that is not done the rest is not attempted.
Items written before it stay written: nothing is rolled back. The
result says per item: `done`, `partial` (some steps done; `detail` says which and what to do
next), `failed`, `refused_changed` (the state changed since you approved), `unknown_after_timeout`
(the request timed out; it is reported with the state read afterwards and never repeated) or
`not attempted`.

**Secrets go to files, not to the model.** Profiles, download links, generated passwords and
the support report are saved in `OPENVPN_AS_OUTPUT_DIR` (default `<config dir>/output`,
created for your user only; files are readable by you only) and the tool returns the path.
A profile file is named `<date>-<time>-profile-userlocked-<user>.ovpn` or
`<date>-<time>-profile-autologin-<user>.ovpn`, and a download link file carries the same
two words, so the name tells the kind of profile.
A `~` at the start of `OPENVPN_AS_OUTPUT_DIR` is your home folder. Give a full path: a relative
one is taken from the working directory of the server process, which your AI app chooses. A
folder that exists already keeps its permissions; only the files are made private.
There is no way to pass a password to a tool. Delete a file once it has been delivered. An
agent that can read files on your machine (Claude Code, Codex) can read this folder too.

**Audit log.** Every change the server tried, and every one it refused or you cancelled, is
one JSON line per item in `<config dir>/audit.jsonl`: time, tool, target, outcome, approval
mode, server, the state before and after. A call whose arguments are invalid by themselves
(for example `update_user` with `deny=true`, or no field at all) is turned down before any
check and leaves no line. Saving a support report changes nothing and leaves no line either.
Secrets are not written to the log. The file is not rotated.

**Blocking a user.** `block_user` sets `deny` and disconnects, because Access Server does not
end a running session when a user is blocked. `update_user` with `deny=false` unblocks.
Blocking a group or moving a user into a blocked group does not disconnect anyone; the
approval text and the result name the connected users, and `disconnect_vpn_sessions` ends
their sessions. Deleting a group does not disconnect anyone either; the approval text lists
its members.

**Access Server versions.** Write mode is tested on Access Server 3.1 and 3.2. On a newer
version every approval text and result carries a warning that the version is not on the
tested list; below 3.1, or when the version cannot be read, writes are refused.

Known limits of this release:

- Access Server refuses the VPN connections of the members of a **new group** until the server
  is restarted (measured on 3.1.0 and 3.2.4). `create_group` says so; restart with
  `warm_restart`. Access Server cannot tell whether a group still waits for a restart;
  as-mcp-server knows it only for the groups it created itself.
- Download links cannot be listed or revoked. Blocking the user later does not stop an unused
  link, though the downloaded profile cannot connect while the user is blocked.
- An existing user cannot get a new password.
- Access rules, access lists and server settings cannot be changed.

## Configuration reference

| Variable | Default | Meaning |
| --- | --- | --- |
| `OPENVPN_AS_URL` | from `setup` | `https://host[:943]` |
| `OPENVPN_AS_USER` | from `setup` | admin username |
| `OPENVPN_AS_PASSWORD` | from the OS keyring | password |
| `OPENVPN_AS_CA_CERT` | - | PEM file of a private CA that signed the server certificate |
| `OPENVPN_AS_INSECURE` | `false` | `true` disables TLS verification. Loud: a warning is logged and `connection_info` reports it. Test servers only. |
| `OPENVPN_AS_TIMEOUT` | `30` | request timeout in seconds |
| `OPENVPN_AS_LOG_LEVEL` | `WARNING` | `DEBUG`, `INFO`, `WARNING`, `ERROR`; logs go to stderr and never contain secrets |
| `OPENVPN_AS_CONFIG_DIR` | `~/.config/as-mcp-server` | where `profiles.toml` and `audit.jsonl` live |
| `OPENVPN_AS_WRITE_TOOLS` | `false` | `true` registers the tools that change the server ([Write mode](#write-mode)) |
| `OPENVPN_AS_APPROVAL` | `prompt` | `prompt`: ask before every change. `auto`: do not ask (with the limits listed under Write mode) |
| `OPENVPN_AS_OUTPUT_DIR` | `<config dir>/output` | folder for profiles, download links, generated passwords and support reports |

Reserved for later releases, not implemented yet: `OPENVPN_AS_PROFILE`, `OPENVPN_AS_TOOLS`,
`OPENVPN_AS_EXTRA_HEADERS`.

Remove stored credentials with `uvx --python 3.13 as-mcp-server setup --clear`.

## Logs and debugging

- The server logs to stderr only; `OPENVPN_AS_LOG_LEVEL=DEBUG` adds one line per request
  (`METHOD /path -> status in N ms`) and the background token renewals. Bodies, headers,
  passwords and tokens are never logged. The level applies to as-mcp-server's own lines;
  the libraries it uses log from WARNING up.
- The reliable way to read the log is a terminal: `OPENVPN_AS_LOG_LEVEL=DEBUG uvx
  --python 3.13 as-mcp-server check` performs the same login and `GET /server/info` as the
  `connection_info` tool and prints the log next to the result.
- Inside an agent, where stderr ends up is the agent's business. Claude Code has no log view
  in its `/mcp` panel (it offers View tools, Reconnect and Disable). It keeps a file per
  session in `~/Library/Caches/claude-cli-nodejs/<project>/mcp-logs-<server>/*.jsonl` on
  macOS (`~/.cache/claude-cli-nodejs/...` on Linux) with its own records (which tool was
  called, how long it took) and one `Server stderr: ...` record with what the server wrote
  while it started. The per-request `DEBUG` lines are not in that file (checked with Claude
  Code 2.1.329, `claude -p`), although the server writes them: use the terminal `check`
  above for those. `claude --debug` (or `--debug-file <path>`) turns on Claude Code's own
  debug log, which includes its MCP connection messages.
- `OPENVPN_AS_TIMEOUT=60` if the server is slow (default 30 s).

## MFA and other second sign-in steps

If the admin account needs a second step, the first tool call reports it and quotes the
server's own prompt. For Access Server's built-in authenticator that is the 6-digit TOTP code;
for a RADIUS, LDAP or PAM back end it is whatever the back end asks for (a PIN, a Duo passcode,
an answer to a question), passed through word for word. The agent shows you the prompt, asks
for the answer and calls `login`. The session then lasts for the lifetime of the MCP process:
Access Server issues short-lived tokens (10 minutes by default), and the server renews its
token in the background before it expires, so you are asked again only after the limit Access
Server puts on renewals (4 hours by default), or if the machine slept past a token's expiry.

The answer goes to the challenge the server already issued, so a push- or SMS-based back end
is not triggered a second time, as long as you answer within about 90 seconds (Access Server
forgets a challenge after two to three minutes). After a wrong answer or a longer pause the
server issues a new challenge; if it asks a different question, the agent quotes it before
anything is sent. Authenticator codes are single-use and must be exactly six digits (a
mistyped code is refused locally and does not count as a failed attempt); more than five
wrong answers lock the account for 15 minutes (Access Server default).

### SAML-only accounts

as-mcp-server signs in with a username and password, plus the answer to a second step when
asked. It cannot
complete the browser-based SAML flow. When the Access Server's default authentication system is
SAML, an admin account that follows that default is refused with an error that says so, and no
MFA code is requested (a code could never succeed). Use an administrator whose authentication
method is set per user to something else: `list_users` shows it as `auth_method` (`sacli` calls
it `user_auth_type`), and the built-in `openvpn` administrator uses `local`.

## Security notes

- Your password never enters the conversation: `setup` is a terminal command. Only the
  answer to a second sign-in step passes through the agent: a 30-second, single-use
  authenticator code, or whatever a RADIUS, LDAP or PAM back end asks for. A static PIN or
  passcode given this way reaches the model provider like any other tool argument; if that
  is not acceptable, use an admin account whose second step is a one-time code.
- Tool responses go to your agent's model provider. The server redacts TOTP secrets, which
  Access Server otherwise includes in user listings, the subscription key from the license
  information, and configuration values whose key name looks like a secret (passwords,
  bind passwords, tokens, private keys, the subscription bundle; a trailing version or
  index such as `.2.9.0` does not hide the name) or that Access Server itself marks as
  redacted, in `get_status_overview`; everything else in a response (user names, addresses,
  log entries, other configuration values) is visible to the model.
- Log records and the list of connected clients contain text that anyone on the internet
  can choose: a failed login is logged with the username exactly as typed, and VPN clients
  report their own platform and version. Such text can be written to look like log lines
  or instructions for the model. `get_log_reports` and `get_active_vpn_connections` show a
  client-chosen username, certificate name, platform, version or proxied address only when
  it looks like a plain value; anything else (for example newlines, control or invisible
  characters, sentence punctuation, more than three words, more than 64 characters or
  16 East Asian characters) is replaced by
  `{"withheld": true, "length": ..., "flags": [...], "fingerprint": ...}` without the text.
  The same fingerprint means the same text. Read the full records in the Access Server
  Admin UI if you need them. This is a heuristic: a short plain-looking string such as
  `ignore_previous_instructions` still gets through, so treat a model's security summary
  as a draft all the same.
- Tool calls are rate limited: 30 in a row, then 30 per minute (one every two seconds). An
  agent stuck in a loop gets a tool error that tells it how long to wait instead of sending
  Access Server a request per call. Listing the tools and connecting are never limited. The
  limiter counts tool calls: on newer MCP clients one approved change is two calls (the
  question and the answer), so about 15 approved changes per minute; in automatic approval
  mode one list call carries up to 100 changes.
- Write mode: text from the server or from a web page can make a model *propose* a change
  (prompt injection), but only you can approve it. `OPENVPN_AS_APPROVAL=auto` removes that
  check, which is why it has hard limits. Read the approval text before you say yes.
- Use a dedicated admin account so its lockout or revocation affects only the agent.
- The keyring item is bound to the Python binary on macOS; after a `uvx` upgrade, or the
  first run with another `--python`, the system may ask once whether the new binary may read
  it.
- See `SECURITY.md` for reporting.

## Compatibility

| Access Server | Result |
| --- | --- |
| 3.2.4 | all tools verified, read and write |
| 3.1.0 | all tools verified, read and write |
| 3.0.x | not supported (Web API v0.1) |

The Web API is declared unstable by OpenVPN; an Access Server upgrade that changes it needs a
matching `as-mcp-server` release. Please open an issue with the server version if a tool
stops working.

## Roadmap and feedback

0.2.0 adds the first write operations behind an explicit opt-in. Later releases may add
access rules, access lists and applying server changes. Tell us what is missing with the
**Tool request** issue template and report problems with **Bug report**.

## Development

    make install      # uv sync
    make check        # ruff + pytest (no network)
    make stand-up     # two real Access Servers and FreeRADIUS in Docker, see dev/README.md
    make live         # tests against them
    make release-build  # the package as published: dependency versions pinned to uv.lock

Agent instructions: `AGENTS.md`.
