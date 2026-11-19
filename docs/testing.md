# Manual test checklist

Automated tests cover the tools against real Access Servers (`make live`) and what a headless
agent does with them (`dev/evals.py`). They cannot cover a person looking at an approval
question in a real app. This checklist does. Fill one table per release.

## Setup

- An Access Server you may change (the dev stand of `dev/README.md` is enough), an admin
  account for the agent, and throwaway names for everything you create (`qa-u1`, `qa-g1`).
- Add the server to the app with `OPENVPN_AS_WRITE_TOOLS=true`. Leave `OPENVPN_AS_APPROVAL`
  unset unless a check says `auto`.
- `uvx --python 3.13 as-mcp-server check` must print `Writes:   on (OPENVPN_AS_WRITE_TOOLS=true), approval:
  prompt`.
- After each run look at `<config dir>/audit.jsonl` and at the files in
  `<config dir>/output`.

## Checks per app

| # | Do | Expect |
| --- | --- | --- |
| 1 | "Create user qa-u1 with a generated password" | The app shows the approval question with the server URL, `Action: Create user (1 item): qa-u1`, a `Total:` line and the lines of the change. The model does not answer it for you. |
| 2 | Answer yes | The answer names a file path and no password. The file holds the password and is readable by you only. `audit.jsonl` has a line with outcome `applied`. |
| 3 | "Block user qa-u1", answer no (decline) | "Cancelled by the admin; nothing was changed." word for word. The user is not blocked. The agent does not try again or another way. Audit line `cancelled`. |
| 4 | The same, and close or cancel the question instead of answering | The same as 3. |
| 5 | "Set totp to true for these 100 users: ..." (create them first, or use `auto` to create) | One question listing 100 targets. Can you read it? Can you scroll it? Note how the app shows a long text. |
| 6 | In an app or mode without elicitation (if there is one) ask for any change | "Your AI app cannot show an approval prompt, so as-mcp-server did not make this change. ..." word for word, nothing changes, audit line `refused_no_approval`. |
| 7 | "Make qa-u1 an administrator" with `OPENVPN_AS_APPROVAL=auto` | Refused: "Refused in automatic approval mode: user qa-u1 would become an administrator. ..." relayed word for word. Not an administrator afterwards. |
| 8 | "Remove the admin right from <the agent's own account>" | Refused: "Refused: this change would lock as-mcp-server out of its own admin account ..." word for word. |
| 9 | "Generate a connection profile for qa-u1" and approve | A path to an `.ovpn` file; no certificate or key text in the conversation. Does the agent read the file back without being asked? It must not. |
| 10 | Connect a VPN client as qa-u1, then "Delete user qa-u1" and approve | The question says how many profiles are deleted and how many sessions are disconnected. The client is disconnected, the user is gone. |
| 11 | "Create group qa-g1" and approve | The question and the answer both say that members cannot connect until Access Server is restarted. The agent offers `warm_restart` and does not call it by itself. |
| 11a | "Move qa-u1 into qa-g1" and approve, then "restart the server" | The first question has the line "the group applies fully to the user only after a warm restart (warm_restart)". The restart question says `Action: Warm restart (1 item): Access Server` and how many VPN clients are connected. After yes: a new `last_restarted` in "get server status". |
| 11b | "Restart the server" with `OPENVPN_AS_APPROVAL=auto` | The question is still shown. In an app that cannot show it: "Refused: a warm restart always needs the administrator's approval, ..." word for word, no restart. |
| 12 | Ask for a change, then change the same user in the Admin UI before you answer yes | "Changed on the server since the preview; nothing was written." word for word. The agent does not run the request again by itself. |
| 13 | "Create a support report" | No question. A path and a size; no report text in the conversation. |
| 14 | Clean up: delete `qa-u1`, `qa-g1` and the files in the output folder | - |

Windows only: the files in the output folder are readable by your user and by administrators
of the machine, not by other users.

## Results

Required for a release: Claude Code (interactive), Claude Desktop, Codex. Optional: Cursor,
VS Code, OpenCode. Write the check numbers that failed, or "all".

Claude Desktop does not show the approval question, so only checks 6, 7, 8 and 13 are
required for it; the other checks need the question (11b: the refusal). It also rewords refusals (checks 7 and
8): a known limit, the texts were left as they are.

### 0.2.0

| App | Version | OS | Access Server | Date | Tester | Result |
| --- | --- | --- | --- | --- | --- | --- |
| Claude Code (interactive) | | | | | | not run yet |
| Claude Desktop | | | | | | not run yet |
| Codex | | | | | | not run yet |
| Cursor (optional) | | | | | | |
| VS Code (optional) | | | | | | |
| OpenCode (optional) | | | | | | |

Run by the developer, not a person at an app: both protocol eras over a real stdio
connection with approve, decline, cancel and no elicitation (checks 1-4, 6, 12 as automated
tests), and headless Claude Code, which cannot answer the question and gets check 3.
