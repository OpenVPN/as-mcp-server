# Test fixtures

Real responses captured from the dev stand (`dev/compose.yaml`), on 2026-09-09 unless the note
gives a later date:
`as-3-2-2` = Access Server 3.2.2 (413ca39f), `as-3-1-0` = Access Server 3.1.0 (e22fe316). Unless the
note says `3.1.0`, a fixture comes from 3.2.2. Every file has the shape
`{"status": <HTTP status>, "note": "<how it was produced>", "body": <JSON body>}`.

Sanitised: every auth token is `SESS_TOKEN_test`; the TOTP secret is the RFC example value
`JBSWY3DPEHPK3PXP`; no password appears anywhere. `totp_secret` / `mfa_secret` keys are kept
on purpose: tests assert that the server redacts them.

| file | status | note |
| --- | --- | --- |
| `access_rules.json` | 200 | rules of the staff ruleset |
| `access_rules_filter_type.json` | 200 | type + match_data filters |
| `access_rulesets_all.json` | 200 | no owner = everything |
| `access_rulesets_default.json` | 200 | global owner spelled __DEFAULT__ |
| `access_rulesets_staff.json` | 200 | group owner |
| `default_user.json` | 200 |  |
| `error_bad_owner_400.json` | 400 | documented DEFAULT is rejected |
| `error_bad_ruleset_400.json` | 400 |  |
| `error_forbidden_403.json` | 403 | admin endpoint with a non-admin token |
| `error_invalid_token_401.json` | 401 | any authenticated endpoint |
| `error_missing_header_400.json` | 400 | no X-OpenVPN-As-AuthToken header |
| `error_not_found_404.json` | 404 | endpoint absent on AS 3.1-3.2.2 |
| `groups_list.json` | 200 | members counted only |
| `groups_list_members.json` | 200 | members enumerated |
| `license_info_subscription.json` | 200 | trial subscription active |
| `license_info_unlicensed.json` | 200 | AS 3.1.0 without a subscription |
| `log_reports.json` | 200 | latest 5 |
| `log_reports_anywhere.json` | 200 | anywhere filter |
| `log_reports_injected.json` | 200 | 3.2.2: failed logins with crafted usernames (log lines, instructions, control and bidi characters) sent without credentials, plus plain failures for alice and bob (captured 2026-09-29) |
| `log_reports_errors_only.json` | 200 | error is a string filter: not_equal empty string |
| `log_reports_filter_time.json` | 200 | relative time filter |
| `log_reports_filter_user.json` | 200 | username filter |
| `login_bad_password_403.json` | 403 |  |
| `login_challenge_radius_401.json` | 401 | 3.2.2: admin bound to a RADIUS back end (dev FreeRADIUS) that answers Access-Challenge; `challenge` is the RADIUS Reply-Message verbatim (captured 2026-09-22) |
| `login_radius_bad_password_403.json` | 403 | 3.2.2: wrong first-factor password for a RADIUS-bound admin; the RADIUS Reply-Message is passed through as `reason` |
| `login_lockout_403.json` | 403 | 3.2.2: after repeated authentication failures (captured from curl) |
| `login_mfa_required_401.json` | 401 | 3.2.2: enrolled TOTP admin, no totp in body; MFAChallenge fields are top-level |
| `login_mfa_required_401_3_1_0.json` | 401 | 3.1.0: enrolled TOTP admin, no totp in body; MFAChallenge fields are top-level |
| `login_mfa_totp_inline_3_1_0.json` | 500 | 3.1.0: totp passed inline in /auth/login/userpassword |
| `login_mfa_totp_inline_500.json` | 500 | 3.2.2: totp passed inline in /auth/login/userpassword -> server error (bug); use /auth/login/mfaauth instead |
| `login_mfa_totp_inline_bad_code_500.json` | 500 | 3.2.2: totp passed inline in /auth/login/userpassword -> server error (bug); use /auth/login/mfaauth instead |
| `login_not_admin.json` | 403 | non-admin user with request_admin=true |
| `login_ok.json` | 200 | admin login without MFA, AS 3.2.2 |
| `login_saml_required_401.json` | 401 | 3.2.2 with `auth.module.type=saml`: password login of an account without a per-user auth type; no `challenge_context` (captured 2026-09-21) |
| `mfa_enroll_ok.json` | 200 | enrollment with the intermediate 409 token |
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
| `server_info.json` | 200 |  |
| `server_info_3_1_0.json` | 200 | AS 3.1.0 |
| `server_status.json` | 200 |  |
| `status_overview.json` | 200 | empty names |
| `status_overview_with_names.json` | 200 | two config keys requested |
| `status_overview_secrets.json` | 200 | secret-bearing config keys (LDAP bind password, RADIUS secret, subscription bundle); shape captured 2026-09-16, values replaced |
| `status_overview_versioned_secret.json` | 200 | `acme.eab_hmac_key.2.9.0`, a secret-shaped key with a version suffix, planted with `sacli ConfigPut`; captured 2026-09-22, value replaced |
| `token_renew_ok.json` | 200 |  |
| `users_list.json` | 200 | all users (openvpn, mfa-admin, alice) |
| `users_list_by_names.json` | 200 | explicit usernames; missing one is silently absent |
| `users_list_filter_admin.json` | 200 | admin filter |
| `users_list_filter_name.json` | 200 | name substring filter |
| `vpn_status.json` | 200 | no clients connected |
| `vpn_status_connected.json` | 200 | 2026-10-02, one autologin client of `qa vpn test user`; the certificate name arrives as `common_name` (the API document says `commonname`) |
