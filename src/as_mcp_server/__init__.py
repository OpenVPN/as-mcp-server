"""Local MCP server for OpenVPN Access Server administrators (read-only)."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("as-mcp-server")
except PackageNotFoundError:  # running from a source tree without an installed dist
    __version__ = "0.0.0"

from as_mcp_server.cli import main

__all__ = ["__version__", "main"]
