"""`python -m as_mcp_server` runs the command line."""

from __future__ import annotations

import sys

from as_mcp_server.cli import main

if __name__ == "__main__":
    sys.exit(main())
