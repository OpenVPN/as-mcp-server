# Test fixtures

Real responses captured from the dev stand (`dev/compose.yaml`), on 2026-09-09 unless the note
gives a later date:
`as-latest` (named `as-3-2-2` until 2026-11-12) = Access Server 3.2.2 (413ca39f) until 2026-11-12, then 3.2.3 (8444f22d) until 2026-11-13, then 3.2.4 (f3c295a7); `as-3-1-0` = Access Server 3.1.0 (e22fe316). Unless the
note names another version, a fixture comes from 3.2.2. Every file has the shape
`{"status": <HTTP status>, "note": "<how it was produced>", "body": <JSON body>}`.

Sanitised: every auth token is `SESS_TOKEN_test`; the TOTP secret is the RFC example value
`JBSWY3DPEHPK3PXP`; no password appears anywhere. `totp_secret` / `mfa_secret` keys are kept
on purpose: tests assert that the server redacts them.

| file | status | note |
| --- | --- | --- |
| `access_lists.json` | 200 | 3.2.4: every access list, one entry of each shape: route, nat, a deny, services (port, port range, ICMP type), `user`, `group`, `all`, `all_vpn_clients`, `all_s2c_subnets`, `access_from_ipv4`, a non-Latin owner. The IPv6 list of `contractors` exists on the server and is absent here (captured 2026-11-13) |
| `access_lists_3_1_0.json` | 200 | the same on 3.1.0 |
| `access_rules.json` | 200 | rules of the staff ruleset |
| `access_rules_filter_type.json` | 200 | type + match_data filters |
| `access_rulesets_all.json` | 200 | no owner = everything |
| `access_rulesets_default.json` | 200 | global owner spelled __DEFAULT__ |
| `access_rulesets_staff.json` | 200 | group owner |
| `contract_0_1_0.json` | - | not a server response: the tool list of tag `v0.1.0` (name, description, inputSchema, annotations), dumped through an in-memory MCP client; `tests/test_contract.py` compares against it. Two deliberate changes in 0.2.0: the description of `get_server_info` (hostname is not `host.name`) and one more sentence in the description of `list_users` (access lists are read with `list_access_lists`) |
| `default_user.json` | 200 |  |
| `error_bad_owner_400.json` | 400 | documented DEFAULT is rejected |
| `error_bad_ruleset_400.json` | 400 |  |
| `error_forbidden_403.json` | 403 | admin endpoint with a non-admin token |
| `error_group_exists_400.json` | 400 | 3.2.4: the same request again (captured 2026-11-14) |
| `error_invalid_token_401.json` | 401 | any authenticated endpoint |
| `error_missing_header_400.json` | 400 | no X-OpenVPN-As-AuthToken header |
| `error_not_found_404.json` | 404 | endpoint absent on AS 3.1-3.2.2 |
| `error_password_not_local_403.json` | 403 | 3.2.4: the user's authentication method is pam (captured 2026-11-14) |
| `error_password_policy_403.json` | 403 | 3.2.4: a password without a digit, an upper-case letter and a symbol (captured 2026-11-14) |
| `error_user_exists_400.json` | 400 | 3.2.4: the same request again (captured 2026-11-14) |
| `error_userprop_missing_user_400.json` | 400 | 3.2.4: POST /userprop/set for a name without a record (captured 2026-11-14) |
| `error_users_delete_404.json` | 404 | 3.2.4: the same request again: the user is gone (captured 2026-11-14) |
| `groups_create_201.json` | 201 | 3.2.4: POST /groups/create {"name": "fixture-group"}; the body is empty (captured 2026-11-14) |
| `groups_delete_204.json` | 204 | 3.2.4: POST /groups/delete {"groups": ["fixture-group"]}; no body (captured 2026-11-14) |
| `groups_list.json` | 200 | members counted only |
| `groups_list_members.json` | 200 | members enumerated |
| `license_info_subscription.json` | 200 | trial subscription active |
| `license_info_unlicensed.json` | 200 | AS 3.1.0 without a subscription |
| `log_reports.json` | 200 | latest 5 |
| `log_reports_anywhere.json` | 200 | anywhere filter |
| `log_reports_errors_only.json` | 200 | error is a string filter: not_equal empty string |
| `log_reports_filter_time.json` | 200 | relative time filter |
| `log_reports_filter_user.json` | 200 | username filter |
| `log_reports_injected.json` | 200 | 3.2.2: failed logins with crafted usernames (log lines, instructions, control and bidi characters) sent without credentials, plus plain failures for alice and bob (captured 2026-09-29) |
| `login_bad_password_403.json` | 403 |  |
| `login_challenge_radius_401.json` | 401 | 3.2.2: admin bound to a RADIUS back end (dev FreeRADIUS) that answers Access-Challenge; `challenge` is the RADIUS Reply-Message verbatim (captured 2026-09-22) |
| `login_lockout_403.json` | 403 | 3.2.2: after repeated authentication failures (captured from curl) |
| `login_mfa_required_401.json` | 401 | 3.2.2: enrolled TOTP admin, no totp in body; MFAChallenge fields are top-level |
| `login_mfa_required_401_3_1_0.json` | 401 | 3.1.0: enrolled TOTP admin, no totp in body; MFAChallenge fields are top-level |
| `login_mfa_totp_inline_3_1_0.json` | 500 | 3.1.0: totp passed inline in /auth/login/userpassword |
| `login_mfa_totp_inline_500.json` | 500 | 3.2.2: totp passed inline in /auth/login/userpassword -> server error (bug); use /auth/login/mfaauth instead |
| `login_mfa_totp_inline_bad_code_500.json` | 500 | 3.2.2: totp passed inline in /auth/login/userpassword -> server error (bug); use /auth/login/mfaauth instead |
| `login_not_admin.json` | 403 | non-admin user with request_admin=true |
| `login_ok.json` | 200 | admin login without MFA, AS 3.2.2 |
| `login_radius_bad_password_403.json` | 403 | 3.2.2: wrong first-factor password for a RADIUS-bound admin; the RADIUS Reply-Message is passed through as `reason` |
| `login_saml_required_401.json` | 401 | 3.2.2 with `auth.module.type=saml`: password login of an account without a per-user auth type; no `challenge_context` (captured 2026-09-21) |
| `mfa_enroll_ok.json` | 200 | enrollment with the intermediate 409 token |
| `mfa_reset_ok.json` | 200 | 3.2.4 (same on 3.1.0): POST /userprop/mfa/generate-secret {username, reset_secret: true, locked: false} for an enrolled user; afterwards totp_locked is false and mfa_status pending (captured 2026-11-27) |
| `mfa_reset_unknown_user_creates_record.json` | 200 | 3.2.4 (same on 3.1.0): the same call for a name with no user record answers 200 and creates a user record of that name (captured 2026-11-27) |
| `mfaauth_bad_code.json` | 403 | 3.2.2: wrong TOTP code |
| `mfaauth_bad_code_3_1_0.json` | 403 | 3.1.0: wrong TOTP code |
| `mfaauth_bad_context.json` | 403 | 3.1.0: unknown challenge_context |
| `mfaauth_missing_context.json` | 403 | 3.1.0: challenge_context omitted |
| `mfaauth_ok.json` | 200 | 3.2.2: challenge/response with a correct code |
| `mfaauth_ok_3_1_0.json` | 200 | 3.1.0: challenge/response with a correct code |
| `mfaauth_radius_bad_answer.json` | 403 | 3.2.2: RADIUS challenge answered with a wrong PIN; the API says `Login failed`, the server log carries the Reply-Message |
| `mfaauth_radius_ok.json` | 200 | 3.2.2: RADIUS challenge answered with the correct PIN through /auth/login/mfaauth |
| `mfaauth_replayed_code.json` | 403 | 3.2.2: same TOTP code used twice within one 30 s window |
| `mfaauth_replayed_code_3_1_0.json` | 403 | 3.1.0: same TOTP code used twice within one 30 s window |
| `password_change_existing_ok.json` | 200 | 3.2.4 (same on 3.1.0): POST /auth/password/change for an existing local user with a VPN session; the session stays up, the old password is refused at once (captured 2026-11-27) |
| `password_change_ok.json` | 200 | 3.2.4: POST /auth/password/change for a local user, by an administrator (captured 2026-11-14) |
| `profile_create_201.txt` | 201 | 3.2.4: the answer of `/profiles/create` (an .ovpn file) for a `userlogin` profile, captured 2026-11-13; the private key, the TLS-Crypt key and every certificate are replaced by `TESTKEY`, `TESTSTATICKEY`, `TESTCERT`, the host by `as.example` |
| `profiles_list.json` | 200 | 3.2.4: all 7 connection profiles ordered by serial (alice 1, bob 4, жанна 1, one autologin); serials arrive as strings (captured 2026-11-13) |
| `profiles_list_3_1_0.json` | 200 | the same on 3.1.0 |
| `rules_modify_update.json` | 200 | 3.2.4 (same on 3.1.0): POST /access/rules/modify with an existing rule (its id) in add and another id in delete; added holds the id of the updated rule (captured 2026-11-27) |
| `ruleset_update_ok.json` | 200 | 3.2.4 (same on 3.1.0): POST /access/rulesets/update {id, name, comment}; without comment it is 400 "comment: Field required" (captured 2026-11-27) |
| `rulesets_list_two_owners.json` | 200 | 3.2.4 (same on 3.1.0): POST /access/rulesets/list {}, the rows of one rule set assigned to a user and a group: one row per owner, each with its own position (captured 2026-11-27) |
| `server_info.json` | 200 | AS 3.2.4 (f3c295a7), captured 2026-11-13 after the stand moved from 3.2.3 |
| `server_info_3_1_0.json` | 200 | AS 3.1.0 |
| `server_status.json` | 200 |  |
| `status_overview.json` | 200 | empty names |
| `status_overview_secrets.json` | 200 | secret-bearing config keys (LDAP bind password, RADIUS secret, subscription bundle); shape captured 2026-09-16, values replaced |
| `status_overview_versioned_secret.json` | 200 | `acme.eab_hmac_key.2.9.0`, a secret-shaped key with a version suffix, planted with `sacli ConfigPut`; captured 2026-09-22, value replaced |
| `status_overview_with_names.json` | 200 | two config keys requested |
| `token_renew_ok.json` | 200 |  |
| `token_url_ok.json` | 200 | the shape of a `/token-url` answer on 3.1.0 and 3.2.4 (`openvpn://import-profile/https://<host>/rest/GetProfileViaToken?token=<32 characters>`), token replaced |
| `users_create_201.json` | 201 | 3.2.4: POST /users/create {"name": "fixture-user"}; the body is empty (captured 2026-11-14) |
| `users_delete_204.json` | 204 | 3.2.4: POST /users/delete {"users": ["fixture-user"]}; no body (captured 2026-11-14) |
| `users_list.json` | 200 | all users (openvpn, mfa-admin, alice) |
| `users_list_by_names.json` | 200 | explicit usernames; missing one is silently absent |
| `users_list_filter_admin.json` | 200 | admin filter |
| `users_list_filter_name.json` | 200 | name substring filter |
| `vpn_status.json` | 200 | no clients connected |
| `vpn_status_connected.json` | 200 | 2026-10-02, one autologin client of `qa vpn test user`; the certificate name arrives as `common_name` (the API document says `commonname`) |
