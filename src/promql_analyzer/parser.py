"""Thin PromQL parsing layer over ``promql-parser``."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import promql_parser

if TYPE_CHECKING:
    from promql_parser import Expr


class PromQLSyntaxError(ValueError):
    """Raised when a query cannot be parsed as valid PromQL.

    Attributes:
        query: Original query text.
        message: Human-readable summary suitable for users and CI logs.
        location: Optional location hint (for example ``"line 1, column 4"``).
        parser_detail: Raw parser detail (included in ``str(error)`` only when
            ``debug=True`` was requested at construction time).
    """

    def __init__(
        self,
        query: str,
        message: str,
        *,
        location: str | None = None,
        parser_detail: str | None = None,
        debug: bool = False,
    ) -> None:
        self.query = query
        self.message = message
        self.location = location
        self.parser_detail = parser_detail
        self.debug = debug

        parts = [f"Invalid PromQL: {message}"]
        if location:
            parts.append(f"({location})")
        if debug and parser_detail:
            parts.append(f"[parser: {parser_detail}]")
        super().__init__(" ".join(parts))


# Public alias preferred in documentation and CI-facing messaging.
InvalidPromQL = PromQLSyntaxError


def parse_query(query: str, *, debug: bool = False) -> Expr:
    """Parse ``query`` into a ``promql-parser`` AST expression.

    Raises:
        PromQLSyntaxError: If the query is not valid PromQL.
        TypeError: If ``query`` is not a string.
    """
    if not isinstance(query, str):
        raise TypeError(f"query must be str, got {type(query).__name__}")

    stripped = query.strip()
    if not stripped:
        raise PromQLSyntaxError(
            query,
            "query is empty",
            debug=debug,
        )

    try:
        return promql_parser.parse(stripped)
    except Exception as exc:  # noqa: BLE001 - parser raises various errors
        raw = str(exc) or exc.__class__.__name__
        message, location = _summarize_parser_error(raw)
        raise PromQLSyntaxError(
            query,
            message,
            location=location,
            parser_detail=raw,
            debug=debug,
        ) from exc


def _summarize_parser_error(raw: str) -> tuple[str, str | None]:
    """Convert a raw parser error into a concise message and optional location."""
    location = _extract_location(raw)
    cleaned = " ".join(raw.strip().split())
    if not cleaned:
        return "unable to parse query", location

    # Prefer a short prefix; keep enough context to be actionable.
    if len(cleaned) > 160:
        cleaned = cleaned[:157] + "..."
    return cleaned, location


def _extract_location(raw: str) -> str | None:
    patterns = (
        r"line\s+(\d+)[,\s]+column\s+(\d+)",
        r"at\s+(\d+):(\d+)",
        r"\((\d+):(\d+)\)",
    )
    for pattern in patterns:
        match = re.search(pattern, raw, flags=re.IGNORECASE)
        if match:
            return f"line {match.group(1)}, column {match.group(2)}"
    return None
