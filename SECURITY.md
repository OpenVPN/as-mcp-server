# Security

Report vulnerabilities privately to security@openvpn.com. Do not open a public issue for
them. You will get an acknowledgement within five working days.

Threat model in one paragraph: the server runs on the administrator's machine with the
administrator's own Access Server credentials, started by the agent over stdio. There is no
network listener and no other user. The password lives in the OS keyring (or, by choice, in
the agent's configuration file); a session token lives in process memory only. Anything the
model is shown, it may send to its provider: tool responses are redacted for known secret
keys (`totp_secret`, `mfa_secret`, `pvt_google_auth_secret`, `password`, `auth_token`,
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
plain-looking string still gets through. Responses carry no other credentials in this
read-only release. Tool calls are rate limited (30 in a row, then 30 per minute) so a
looping agent cannot flood Access Server. Malware running as the same OS user is out of
scope, as for every local tool.
