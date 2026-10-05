"""Text that any client can put in front of the model, and how it is withheld.

Access Server logs a failed login with the username exactly as the client typed it, and
connecting clients report their own platform and version strings. None of that needs
credentials, so an attacker can write sentences into the log that a model later reads
as facts or instructions. Measured: marking such text as untrusted does not change what
models report; removing it does. So a client-supplied value reaches the model only when
it looks like a plain value, and is otherwise replaced by a marker without the text.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import unicodedata
from collections.abc import Callable
from typing import Any

NAME_MAX_LENGTH = 64
NAME_MAX_SPACES = 2
NAME_PUNCTUATION = frozenset(".-_@+\\'$# ")
CLIENT_STRING_MAX_LENGTH = 64
CLIENT_STRING_MAX_SPACES = 3
CLIENT_STRING_PUNCTUATION = frozenset(".-_+()/~ ")
# Chinese and Japanese put no spaces between words, so the word limit does not bound a
# sentence written in them; wide (East Asian) characters get a cap of their own.
MAX_WIDE_LETTERS = 16
ERROR_MAX_LENGTH = 300
SERVER_LITERALS = frozenset({"(no username provided)"})

_INVISIBLE_CATEGORIES = frozenset({"Cf", "Co", "Cs", "Cn", "Zl", "Zp"})
_MARKS = frozenset({"Mn", "Mc"})
MAX_MARKS_PER_LETTER = 3
# Code points that render as nothing or as blank space although they are letters or
# marks: Hangul fillers, the combining grapheme joiner, Khmer inherent vowels,
# Mongolian variation selectors, variation selectors (used to smuggle hidden text).
_BLANK_CODE_POINTS = frozenset("\u115f\u1160\u3164\uffa0\u034f\u17b4\u17b5")
_BLANK_RANGES = ((0x180B, 0x180F), (0xFE00, 0xFE0F), (0xE0100, 0xE01EF))
# [v6] with an optional port, or v4:port; the port is ASCII digits and ends the text.
_WITH_PORT = re.compile(r"\[([^\]]+)\](?::[0-9]{1,5})?|([0-9.]+):[0-9]{1,5}")


def _is_blank(ch: str) -> bool:
    code = ord(ch)
    return ch in _BLANK_CODE_POINTS or any(lo <= code <= hi for lo, hi in _BLANK_RANGES)


def _flags(
    value: str, max_length: int, max_spaces: int, allowed: frozenset[str]
) -> list[str]:
    flags = []
    categories = [unicodedata.category(ch) for ch in value]
    wide = sum(unicodedata.east_asian_width(ch) in ("W", "F") for ch in value)
    if len(value) > max_length or wide > MAX_WIDE_LETTERS:
        flags.append("too_long")
    if "Cc" in categories:
        flags.append("control_characters")
    if any(c in _INVISIBLE_CATEGORIES for c in categories) or any(
        _is_blank(ch) for ch in value
    ):
        flags.append("invisible_characters")
    other_spaces = any(
        c == "Zs" and ch != " " for ch, c in zip(value, categories, strict=True)
    )
    if value.count(" ") > max_spaces or "  " in value or other_spaces:
        flags.append("spaces")
    previous_is_letter = False
    marks = 0
    for ch, category in zip(value, categories, strict=True):
        if category in _MARKS and previous_is_letter and marks < MAX_MARKS_PER_LETTER:
            marks += 1
            continue
        marks = 0
        previous_is_letter = ch.isalnum()
        if previous_is_letter or ch in allowed:
            continue
        if category in _INVISIBLE_CATEGORIES | {"Cc", "Zs"} or _is_blank(ch):
            continue
        flags.append("punctuation")
        break
    return flags


def _withheld(value: str, flags: list[str]) -> dict[str, Any]:
    digest = hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()
    return {
        "withheld": True,
        "length": len(value),
        "flags": flags,
        "fingerprint": digest[:12],
    }


def check_name(value: Any) -> Any:
    """A username or certificate name as typed by a client, or a withheld marker."""
    if not isinstance(value, str) or value == "" or value in SERVER_LITERALS:
        return value
    flags = _flags(value, NAME_MAX_LENGTH, NAME_MAX_SPACES, NAME_PUNCTUATION)
    return _withheld(value, flags) if flags else value


def check_client_string(value: Any) -> Any:
    """A platform or version string reported by a client, or a withheld marker."""
    if not isinstance(value, str) or value == "":
        return value
    flags = _flags(
        value,
        CLIENT_STRING_MAX_LENGTH,
        CLIENT_STRING_MAX_SPACES,
        CLIENT_STRING_PUNCTUATION,
    )
    return _withheld(value, flags) if flags else value


def _is_ip_address(text: str) -> bool:
    text = text.strip(" ")
    if match := _WITH_PORT.fullmatch(text):
        text = match[1] or match[2]
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def check_address(value: Any) -> Any:
    """An address a proxy header may have supplied: only IP addresses pass.

    A comma-separated chain (X-Forwarded-For) passes when every part is an address.
    """
    if not isinstance(value, str) or value == "":
        return value
    if len(value) <= 256 and all(_is_ip_address(part) for part in value.split(",")):
        return value
    return _withheld(value, ["not_an_address"])


def clean_server_text(value: Any) -> Any:
    """Server-written text (error reasons): control characters out, length bounded."""
    if not isinstance(value, str):
        return value
    cleaned = "".join(
        " " if unicodedata.category(ch) in _INVISIBLE_CATEGORIES | {"Cc"} else ch
        for ch in value
    )
    if len(cleaned) > ERROR_MAX_LENGTH:
        cleaned = cleaned[:ERROR_MAX_LENGTH] + " (cut)"
    return cleaned


FieldChecks = tuple[tuple[str, Callable[[Any], Any]], ...]
LOG_FIELD_CHECKS: FieldChecks = (
    ("username", check_name),
    ("platform", check_client_string),
    ("version", check_client_string),
    ("gui_version", check_client_string),
    ("proxied_ip", check_address),
)
# The API document names the certificate name commonname; AS 3.1.0 and 3.2.2 send
# common_name (measured 2026-10-02 with a client connected). Both are checked.
VPN_CLIENT_FIELD_CHECKS: FieldChecks = (
    ("username", check_name),
    ("common_name", check_name),
    ("commonname", check_name),
)


def _check_fields(
    item: dict[str, Any], checks: FieldChecks
) -> tuple[dict[str, Any], int]:
    """A copy of item with the listed fields checked, and how many were withheld."""
    item = dict(item)
    withheld = 0
    for field, check in checks:
        if field in item:
            checked = check(item[field])
            if checked is not item[field]:
                withheld += 1
                item[field] = checked
    return item, withheld


def check_log_reports(body: Any) -> Any:
    """get_log_reports: withhold client text in each record, count what was withheld."""
    if not isinstance(body, dict) or not isinstance(body.get("records"), list):
        return body
    withheld = 0
    records = []
    for record in body["records"]:
        if isinstance(record, dict):
            record, count = _check_fields(record, LOG_FIELD_CHECKS)
            withheld += count
            if "error" in record:
                record["error"] = clean_server_text(record["error"])
        records.append(record)
    result = {**body, "records": records}
    if withheld:
        result["withheld_values"] = withheld
    return result


def check_vpn_status(body: Any) -> Any:
    """get_active_vpn_connections: withhold client-chosen names of connected clients."""
    if not isinstance(body, dict) or not isinstance(body.get("vpn_clients"), list):
        return body
    withheld = 0
    clients = []
    for client in body["vpn_clients"]:
        if isinstance(client, dict):
            client, count = _check_fields(client, VPN_CLIENT_FIELD_CHECKS)
            withheld += count
        clients.append(client)
    result = {**body, "vpn_clients": clients}
    if withheld:
        result["withheld_values"] = withheld
    return result
