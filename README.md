# as-mcp-server

A local [MCP](https://modelcontextprotocol.io) server that lets your own AI agent (Claude Code,
Codex, Cursor, VS Code, OpenCode, Claude Desktop, ...) look at your **OpenVPN Access Server**
through its Web API. This release is **read-only**: it answers questions such as "is the VPN
healthy", "who is connected", "who failed to log in today", "what can user X reach" and never
changes anything on the server.

It runs on your machine, is started by your agent, and talks to Access Server with your own
admin credentials. Nothing is hosted by anyone else.

Copyright (c) 2026 OpenVPN Inc. Licensed under the MIT License, see `LICENSE`.

## Requirements

- OpenVPN Access Server **3.1 or newer** (Web API v0.2). Tested on 3.1.0 and 3.2.2.
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

       uvx as-mcp-server setup

   If the account needs a second sign-in step you are asked for it as well, with the server's
   own prompt (the authenticator code, or for example a PIN from a RADIUS back end).
3. Register the server with your agent: run its command from the table in
   [Agent setup](#agent-setup), or add the entry to its configuration file. There is no
   secret in this configuration.
4. Ask the agent something: "Is my VPN healthy?" It will call `get_status_overview`.

Pin a version if you want upgrades to be explicit: `uvx as-mcp-server@0.1.0`. `uvx` keeps
using the version it first cached until you pass `@latest` or run `uv cache clean`.

### Agent setup

| Agent | Command | Configuration file |
| --- | --- | --- |
| Claude Code | `claude mcp add openvpn-as -- uvx as-mcp-server` | `~/.claude.json` (add `--scope user` to use it in every project) |
| Codex CLI | `codex mcp add openvpn-as -- uvx as-mcp-server` | `~/.codex/config.toml` |
| Gemini CLI | `gemini mcp add -s user openvpn-as uvx as-mcp-server` (no `--`) | `~/.gemini/settings.json` |
| OpenCode | `opencode mcp add openvpn-as -- uvx as-mcp-server` | `~/.config/opencode/opencode.json` (or `.jsonc`) |
| VS Code | `code --add-mcp '{"name":"openvpn-as","command":"uvx","args":["as-mcp-server"]}'` | the user profile's `mcp.json` ("MCP: Open User Configuration"), or `.vscode/mcp.json` in a project |
| Cursor | - | `~/.cursor/mcp.json`, or `.cursor/mcp.json` in a project |
| Claude Desktop | - | macOS `~/Library/Application Support/Claude/claude_desktop_config.json`, Windows `%APPDATA%\Claude\claude_desktop_config.json` (Settings, Developer, Edit Config) |

In Windows PowerShell type `claude.cmd` instead of `claude`: PowerShell drops the `--` when it
runs the `claude.ps1` wrapper, and the command then fails.

The entry has a different shape per agent. Claude Desktop, Cursor and Gemini CLI (and Claude
Code's project file `.mcp.json`):

    {
      "mcpServers": {
        "openvpn-as": { "command": "uvx", "args": ["as-mcp-server"] }
      }
    }

VS Code:

    {
      "servers": {
        "openvpn-as": { "type": "stdio", "command": "uvx", "args": ["as-mcp-server"] }
      }
    }

Codex CLI:

    [mcp_servers.openvpn-as]
    command = "uvx"
    args = ["as-mcp-server"]

OpenCode 1.x (the command is one array, the server sits directly under `mcp`):

    {
      "$schema": "https://opencode.ai/config.json",
      "mcp": {
        "openvpn-as": { "type": "local", "command": ["uvx", "as-mcp-server"] }
      }
    }

OpenCode 2 (the server sits under `mcp.servers`):

    {
      "mcp": {
        "servers": {
          "openvpn-as": { "type": "local", "command": ["uvx", "as-mcp-server"] }
        }
      }
    }

Both versions have the `opencode mcp add openvpn-as -- uvx as-mcp-server` command; 1.x writes
the first form.

### Alternative: environment variables (headless Linux, CI, or by preference)

Skip `setup` and give the agent the settings as environment variables of the server entry.
With a command, add one flag per variable: `--env KEY=value` for Codex CLI and OpenCode, `-e
KEY=value` for Gemini CLI and Claude Code. Claude Code reads every word after `-e` as another
variable, so put the server name first:

    claude mcp add openvpn-as -e OPENVPN_AS_URL=https://vpn.example.com:943 \
      -e OPENVPN_AS_USER=mcp-admin -e OPENVPN_AS_PASSWORD=... -- uvx as-mcp-server

In a configuration file the variables go into `env` next to `command` (Claude Desktop, Cursor,
Gemini CLI, VS Code, Claude Code), into `environment` for OpenCode, and into a
`[mcp_servers.openvpn-as.env]` table for Codex CLI:

    {
      "mcpServers": {
        "openvpn-as": {
          "command": "uvx",
          "args": ["as-mcp-server"],
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

    uvx as-mcp-server check

prints the URL, user, where each value came from, TLS mode and the server version. Inside a
conversation the equivalent is the `connection_info` tool, which never fails and reports any
problem in its `error` field.

## Tools

All tools are read-only except `login`, which only creates a session.

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

Responses are the Access Server API's own JSON. `since`/`until` are relative durations such
as `30m`, `24h`, `7d`, `15d 20m`. "What can user X reach": rulesets for the user, for each of
the user's groups, and for `__DEFAULT__`, then `list_access_rules` with the collected ids.

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
| `OPENVPN_AS_CONFIG_DIR` | `~/.config/as-mcp-server` | where `profiles.toml` lives |

Reserved for later releases, not implemented yet: `OPENVPN_AS_PROFILE`, `OPENVPN_AS_TOOLS`,
`OPENVPN_AS_READ_ONLY`, `OPENVPN_AS_EXTRA_HEADERS`.

Remove stored credentials with `uvx as-mcp-server setup --clear`.

## Logs and debugging

- The server logs to stderr only; `OPENVPN_AS_LOG_LEVEL=DEBUG` adds one line per request
  (`METHOD /path -> status in N ms`) and the background token renewals. Bodies, headers,
  passwords and tokens are never logged.
- The reliable way to read the log is a terminal: `OPENVPN_AS_LOG_LEVEL=DEBUG uvx
  as-mcp-server check` performs the same login and `GET /server/info` as the
  `connection_info` tool and prints the log next to the result.
- Inside an agent, where stderr ends up is the agent's business. Claude Code has no log view
  in its `/mcp` panel (it offers View tools, Reconnect and Disable); it writes each server's
  stderr as `Server stderr: ...` records into
  `~/Library/Caches/claude-cli-nodejs/<project>/mcp-logs-<server>/*.jsonl` on macOS
  (`~/.cache/claude-cli-nodejs/...` on Linux), one file per session. `claude --debug` (or
  `--debug-file <path>`) turns on Claude Code's own debug log, which includes its MCP
  connection messages.
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
mistyped code is refused locally and does not count as a failed attempt); five wrong answers
lock the account for 15 minutes (Access Server default).

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
  Access Server a request per call. Listing the tools and connecting are never limited.
- Use a dedicated admin account so its lockout or revocation affects only the agent.
- The keyring item is bound to the Python binary on macOS; after a `uvx` upgrade the system
  may ask once whether the new binary may read it.
- See `SECURITY.md` for reporting.

## Compatibility

| Access Server | Result |
| --- | --- |
| 3.2.2 | all tools verified |
| 3.1.0 | all tools verified |
| 3.0.x | not supported (Web API v0.1) |

The Web API is declared unstable by OpenVPN; an Access Server upgrade that changes it needs a
matching `as-mcp-server` release. Please open an issue with the server version if a tool
stops working.

## Roadmap and feedback

This first release only reads. Later releases may add safe write operations (users, groups, access
rules, profiles) and server administration, each behind explicit opt-in. Tell us what is
missing with the **Tool request** issue template and report problems with **Bug report**.

## Development

    make install      # uv sync
    make check        # ruff + pytest (no network)
    make stand-up     # two real Access Servers and FreeRADIUS in Docker, see dev/README.md
    make live         # tests against them
    make release-build  # the package as published: dependency versions pinned to uv.lock

Agent instructions: `AGENTS.md`.
