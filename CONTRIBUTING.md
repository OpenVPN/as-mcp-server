# Contributing

- Public names are frozen: the 13 tool names, the `OPENVPN_AS_*` variables, the CLI subcommands, `profiles.toml` and the keyring service `as-mcp-server` (see the tables in `README.md`).
- `make install`, then `make check` must be green before every commit; tests never reach the network.
- New tools need: a typed signature, a description that says which question it answers, honest
  `ToolAnnotations`, a fixture captured from a real server (`tests/fixtures/README.md`), and a
  test asserting the request body.
- Anything touching credentials or response redaction gets a test that proves the secret is absent.
- Dependencies: `pyproject.toml` keeps version ranges; change them there, run `uv lock` and
  commit both files. The published package requires exactly the versions in `uv.lock`
  (`make release-build` builds it that way and restores `pyproject.toml`); never commit a
  pinned `pyproject.toml`.
- English only. Small commits, one concern each.

## Releasing

1. Set the version in `pyproject.toml`, run `uv lock`, and move the `[Unreleased]` entries of
   `CHANGELOG.md` under the new version with the release date.
2. Merge to `main`, then tag that commit `v<version>` and push the tag.
3. The `Release` workflow refuses a tag that does not match the version, runs the checks,
   builds the package with the dependency versions from `uv.lock`, and publishes it to PyPI
   once a maintainer approves the `pypi` environment.

## Code of conduct

By taking part you agree to the [Code of Conduct](CODE_OF_CONDUCT.md). Report problems
privately through the address in `SECURITY.md`.
