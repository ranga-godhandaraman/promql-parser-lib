"""Discover PromQL expressions inside structured YAML/JSON documents.

Supports classic Prometheus ``expr`` fields and other common shapes (for
example Osprey-style ``condition`` documents) without requiring a single
schema.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from promql_analyzer.parser import PromQLSyntaxError, parse_query

# Field names that commonly hold PromQL (matched case-insensitively).
KNOWN_PROMQL_KEYS = frozenset(
    {
        "expr",
        "condition",
        "query",
        "promql",
        "expression",
        "alert_condition",
        "promql_expr",
        "promql_query",
        "promql_expression",
    }
)

# Keys whose string values are almost never PromQL (skip heuristic scan).
_SKIP_HEURISTIC_KEYS = frozenset(
    {
        "alert",
        "record",
        "id",
        "name",
        "uid",
        "uuid",
        "description",
        "summary",
        "message",
        "title",
        "subtitle",
        "situation",
        "tip_situation",
        "tip_short_description",
        "runbook",
        "runbook_url",
        "dashboard",
        "severity",
        "team",
        "owner",
        "namespace",
        "kind",
        "apiversion",
        "type",
        "format",
        "version",
        "filename",
        "path",
        "url",
        "href",
        "email",
        "for",
        "interval",
        "timeout",
        "datasource",
    }
)

_PROMQL_SIGNAL = re.compile(
    r"("
    r"\{[^}]*\}|"
    r"\[[^\]]+\]|"
    r"\b(rate|irate|increase|sum|avg|min|max|count|histogram_quantile|"
    r"time|absent|clamp|label_replace|on|ignoring|group_left|group_right)\s*\(|"
    r"[<>!=]=?|"
    r"\b(and|or|unless)\b"
    r")",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ExtractedQuery:
    """A PromQL expression discovered inside a structured document."""

    expr: str
    location: str
    rule_kind: str | None = None  # "alert", "record", "condition", or None
    rule_name: str | None = None


def discover_promql_queries(document: Any, *, path: str = "") -> list[ExtractedQuery]:
    """Walk a parsed document and return PromQL strings found inside it."""
    found: list[ExtractedQuery] = []
    seen: set[tuple[str, str]] = set()
    _walk(document, path=path, out=found, seen=seen)
    return found


def looks_like_promql(text: str) -> bool:
    """Return True when ``text`` has PromQL-like structure (not proven valid)."""
    stripped = text.strip()
    if len(stripped) < 2:
        return False
    if stripped.startswith("{{") or stripped.startswith("${"):
        return False
    # Bare identifiers (alert names, metric names alone) are too ambiguous for
    # heuristic discovery — only accept strings with PromQL structure.
    if _PROMQL_SIGNAL.search(stripped):
        return True
    return False


def parses_as_promql(text: str) -> bool:
    """Return True when ``text`` parses as PromQL."""
    try:
        parse_query(text)
        return True
    except (PromQLSyntaxError, TypeError, ValueError):
        return False


def _walk(
    node: Any,
    *,
    path: str,
    out: list[ExtractedQuery],
    seen: set[tuple[str, str]],
) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            child_path = f"{path}.{key}" if path else str(key)
            if isinstance(key, str) and isinstance(value, str) and value.strip():
                extracted = _candidate_from_field(
                    key=key,
                    value=value.strip(),
                    path=child_path,
                    owner=node,
                )
                if extracted is not None:
                    marker = (extracted.location, extracted.expr)
                    if marker not in seen:
                        seen.add(marker)
                        out.append(extracted)
                    continue
            _walk(value, path=child_path, out=out, seen=seen)
        return

    if isinstance(node, list):
        for index, item in enumerate(node):
            child_path = f"{path}[{index}]" if path else f"[{index}]"
            _walk(item, path=child_path, out=out, seen=seen)


def _candidate_from_field(
    *,
    key: str,
    value: str,
    path: str,
    owner: dict[str, Any],
) -> ExtractedQuery | None:
    key_l = key.lower()
    known = key_l in KNOWN_PROMQL_KEYS

    if known:
        kind, name = _rule_identity(owner)
        return ExtractedQuery(
            expr=value,
            location=path,
            rule_kind=kind,
            rule_name=name,
        )

    if key_l in _SKIP_HEURISTIC_KEYS:
        return None

    if not looks_like_promql(value):
        return None
    if not parses_as_promql(value):
        return None

    if len(value) < 8 and "{" not in value and "[" not in value and "(" not in value:
        return None

    kind, name = _rule_identity(owner)
    return ExtractedQuery(
        expr=value,
        location=path,
        rule_kind=kind,
        rule_name=name,
    )


def _rule_identity(rule: dict[str, Any]) -> tuple[str | None, str | None]:
    if isinstance(rule.get("alert"), str) and rule["alert"].strip():
        return "alert", rule["alert"].strip()
    if isinstance(rule.get("record"), str) and rule["record"].strip():
        return "record", rule["record"].strip()

    context = rule.get("context")
    if isinstance(context, dict):
        for key in ("tip_situation", "name", "id"):
            raw = context.get(key)
            if isinstance(raw, str) and raw.strip():
                return "condition", raw.strip()

    for key in ("name", "title", "id"):
        raw = rule.get(key)
        if isinstance(raw, str) and raw.strip():
            return "condition", raw.strip()

    return None, None
