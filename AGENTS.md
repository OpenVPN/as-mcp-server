# AGENTS.md

Instructions for any AI coding agent (Claude Code, Codex, Cursor, VS Code, OpenCode) working in this repository.

## What this is
`as-mcp-server` is a local stdio MCP server for OpenVPN Access Server administrators.

## Commands
- `make install` - `uv sync` (creates `.venv`)
- `make check` - ruff check + ruff format --check + pytest (must be green before every commit)
- `make test` / `make lint` / `make fmt`
- `make live` - tests against the Docker dev stand (`dev/README.md`), needs `dev/.local/*.env`
- `make release-build` - sdist + wheel as published (dependencies pinned to `uv.lock`, `pyproject.toml` restored)
- `make stand-up` / `make stand-down` - start/stop the dev stand (two Access Servers and FreeRADIUS)
- `uv run python dev/evals.py` - ask a real agent the eval questions on the stand; run it after changing the server instructions or a tool description (`dev/README.md`)
- `uv run as-mcp-server --version|setup|check` - the CLI

## Rules
- English only, everywhere.
- Public names are frozen: tool names, `OPENVPN_AS_*` variables, CLI subcommands, `profiles.toml`, keyring service `as-mcp-server`.
- Never log, print or store passwords, tokens or TOTP secrets. `redact()` in `client.py` lists the keys removed from API responses.
- Tests never reach the network: `httpx.MockTransport` + `tests/fixtures/*.json` (real captured responses, see the README there). Test names are sentences.
- One commit per concern.
- Unknown owner values are placeholders of the form `<MOCK_...>` (none left today); `make placeholders` lists them.
