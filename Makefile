.PHONY: install lint fmt fmt-check test check live live-slow stand-up stand-down build release-build placeholders clean

UV := uv run

install:            ## install dependencies into .venv
	uv sync

lint:               ## ruff check
	$(UV) ruff check .

fmt:                ## ruff format (writes)
	$(UV) ruff format .

fmt-check:          ## ruff format --check
	$(UV) ruff format --check .

test:               ## unit tests (no network)
	$(UV) pytest -q

check: lint fmt-check test   ## everything that must be green before a commit

live-slow:          ## live tests including the ~11 min real token expiry (dev/README.md)
	OPENVPN_AS_LIVE=1 OPENVPN_AS_LIVE_SLOW=1 $(UV) pytest tests/live -v

live:               ## tests against the Docker dev stand (dev/README.md)
	OPENVPN_AS_LIVE=1 $(UV) pytest tests/live -v

stand-up:           ## start the dev stand (both Access Servers and FreeRADIUS)
	docker compose -f dev/compose.yaml --profile compat up -d

stand-down:         ## stop the dev stand
	docker compose -f dev/compose.yaml --profile compat down

build:              ## build sdist + wheel into dist/
	uv build

release-build:      ## build as released: dependencies pinned to uv.lock, pyproject.toml restored
	rm -rf dist && cp pyproject.toml .pyproject.toml.dev && \
	{ uv run --frozen python dev/pin_release.py && uv build && \
	  uv run --frozen python dev/pin_release.py --verify dist/*.whl; }; \
	status=$$?; mv .pyproject.toml.dev pyproject.toml; exit $$status

placeholders:       ## list placeholder values that must be replaced before a release
	@grep -rnE '<(REPLACE_ME[A-Z_]*|MOCK_[A-Z_]+)>' --exclude-dir=.git --exclude-dir=.venv --exclude-dir=dist --exclude-dir=.ruff_cache --exclude-dir=.pytest_cache . && exit 1 || echo "no placeholders left"

clean:
	rm -rf .venv .ruff_cache .pytest_cache dist
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
