# Security

Report vulnerabilities privately to security@openvpn.com. Do not open a public issue for
them. You will get an acknowledgement within five working days.

Threat model in one paragraph: the server runs on the administrator's machine with the
administrator's own Access Server credentials, started by the agent over stdio. There is no
network listener and no other user. The password lives in the OS keyring (or, by choice, in
the agent's configuration file); a session token lives in process memory only. Anything the
model is shown, it may send to its provider: tool responses are redacted for known secret
keys (`totp_secret`, `mfa_secret`, `pvt_google_auth_secret`, `password`, `new_password`, `auth_token`,
`subkey`, `challenge_context`) and, in `get_status_overview`, for configuration values whose key name looks like
a secret (`*secret*`, `*password*`, `*passwd*`, `*bind_pw*`, `*token*`, `*_key`, `*.key`,
`subscription.bundle`, `subscription.saved_state`; a trailing version or index such as
`.2.9.0` is ignored before matching) or that Access Server itself marks with a
`redacted_value`; Access Server hides some of these itself but returns the LDAP bind password
and the subscription bundle in clear text. The answer to a second sign-in step (an
authenticator code, or a PIN a RADIUS, LDAP or PAM back end asks for) passes through the
agent and therefore reaches the model provider. Text chosen by other people reaches the
model too: Access Server logs a failed login with the username as typed, without
credentials, and VPN clients report their own platform and version strings. Such text can
pose as log lines or instructions (prompt injection). `get_log_reports` and
`get_active_vpn_connections` therefore pass a client-chosen username, certificate name,
platform, version or proxied address only when it looks like a plain value and otherwise replace it with a
`{"withheld": true, ...}` marker that carries no part of the text; server-written error
text loses control characters and is capped at 300 characters. This is a heuristic: a short
plain-looking string still gets through. Tool calls are rate limited (30 in a row, then 30 per minute) so a
looping agent cannot flood Access Server. Malware running as the same OS user is out of
scope, as for every local tool.

## Write mode

Write mode (`OPENVPN_AS_WRITE_TOOLS=true`, off by default) lets the agent change users,
groups, connection profiles and sessions. What protects the server then:

- **A person approves every change.** The server builds the approval text itself from the
  state it read (the server, the action, every target, `before -> after`, side effects) and
  asks through MCP elicitation, which the AI app shows to the person; the model cannot answer
  it. Names and values in the text are stripped of line breaks, control and invisible
  characters and cut to a fixed length, so a crafted name cannot add lines to it. The answer
  is bound to the call and to the state that was shown: other arguments, a changed state, a
  reused or unknown answer write nothing. So prompt injection can make a model propose a
  change, and cannot make it happen.
- **`OPENVPN_AS_APPROVAL=auto` removes the person.** It is meant for automation the
  administrator trusts. It is limited in code: no administrator rights are given, MFA is not
  switched off, no authentication method is changed, autologin is not switched on, no
  autologin profile or link is created, and a change whose result cannot be computed is
  refused. Deleting a group is refused when a member would lose MFA, a block or its
  authentication method with it. Everything else, including other deletes and blocks, is
  done without a question. That has a consequence: deleting a user and creating it again
  gives a user without the old MFA enrollment. Do not combine `auto` with an agent that
  reads untrusted text.
- **The account the server signs in with cannot be locked out** in either mode: not blocked,
  deleted, demoted, moved or switched to another authentication method, also not through its
  group.
- **Secrets never reach the model through a tool result.** Profile contents and their private
  keys, download links, generated passwords and the support report are written to files in
  `OPENVPN_AS_OUTPUT_DIR` (folder `0700` when the server creates it, files `0600`, never
  through a symbolic link, never over an existing file); results, approval texts, the audit
  log and the process log hold the path only. A password is never a tool parameter. This
  covers tool results only: an agent with file tools (Claude Code, Codex) can read the output
  folder like any other file of the user. Point `OPENVPN_AS_OUTPUT_DIR` outside the folders
  the agent works in, and delete a file once it has been delivered. On Windows the files rely
  on the permissions of the user profile.
- **Download links cannot be listed or revoked.** A link is limited to 7 days and 5 uses
  (24 hours for an autologin link) and is refused for autologin in `auto`. Blocking the user
  afterwards does not stop an unused link; the profile it returns cannot connect while the
  user is blocked.
- **Every change is recorded.** `<config dir>/audit.jsonl` (file `0600`) gets one line per
  item for every change the server tried, refused or saw cancelled, also when the tool call
  is interrupted while the change is being written: time, tool, target, outcome, approval
  mode, server, administrator, state before and after. Known secret keys are redacted. When
  the line cannot be written before the change, the change is not made. Not recorded: a call
  turned down for its arguments alone, before any check (nothing was read or written), and
  `create_support_report`, which changes nothing. The file is local, is not rotated and is
  not protected against the user who owns it.
- **The server never repeats a write.** A request that times out is reported with the state
  read afterwards, and later items of the same list are not attempted.

Known gaps: blocking a group or moving a user into a blocked group does not disconnect
running sessions (the tools name them); an Access Server version newer than the tested
ones is allowed with a warning; the approval text is plain text, and an app that renders
it as Markdown or HTML may show a crafted name differently from what was written (a name that holds invisible
characters or is cut is marked as such).
