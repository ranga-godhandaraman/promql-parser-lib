"""AST helpers and structurally safe PromQL suggestion transforms."""

from __future__ import annotations

from typing import Any

from promql_parser import (
    AggregateExpr,
    BinaryExpr,
    Call,
    MatchOp,
    MatrixSelector,
    ParenExpr,
    VectorSelector,
)

from promql_analyzer.parser import PromQLSyntaxError, parse_query
from promql_analyzer.rules.ast_utils import metric_name_from_selector, walk_with_ancestors


def unwrap_parens(node: Any) -> Any:
    """Strip nested outer ``ParenExpr`` nodes."""
    while isinstance(node, ParenExpr):
        node = node.expr
    return node


def validate_alternative(original: str, candidate: str) -> str | None:
    """Return ``candidate`` if it parses and differs from ``original``."""
    text = candidate.strip()
    if not text or text == original.strip():
        return None
    try:
        parse_query(text)
    except PromQLSyntaxError:
        return None
    return text


def safe_unwrap_outer_parens(original: str, expr: Any) -> str | None:
    """Suggest unwrapping outermost parentheses when that is the whole query."""
    if not isinstance(expr, ParenExpr):
        return None
    inner = unwrap_parens(expr)
    try:
        candidate = inner.prettify() if hasattr(inner, "prettify") else str(inner)
    except Exception:  # noqa: BLE001
        candidate = str(inner)
    return validate_alternative(original, candidate)


def safe_drop_broad_regex_on_bare_selector(original: str, expr: Any) -> str | None:
    """If query is a selector with only broad ``=~".*"`` matchers, suggest metric alone.

    This is treated as structurally safe for the common case where the matcher
    matches all label values (i.e. is redundant with omitting the matcher).
    """
    node = unwrap_parens(expr)
    if not isinstance(node, VectorSelector):
        return None
    name = metric_name_from_selector(node)
    if not name:
        return None
    matchers = list(node.matchers.matchers) if node.matchers is not None else []
    if not matchers:
        return None

    remaining: list[Any] = []
    dropped = 0
    for matcher in matchers:
        if matcher.name == "__name__" and matcher.op == MatchOp.Equal:
            continue
        if _is_unbounded_regex(matcher):
            dropped += 1
            continue
        remaining.append(matcher)

    if dropped == 0:
        return None
    if remaining:
        # Reconstructing arbitrary matchers safely is non-trivial; only rewrite
        # when *all* user matchers were redundant broad regexes.
        return None
    return validate_alternative(original, name)


def collect_subtree_strings(expr: Any) -> list[str]:
    """Collect prettified strings for non-trivial subexpressions."""
    out: list[str] = []

    def visit(node: Any, _ancestors: tuple[Any, ...]) -> None:
        if isinstance(node, (Call, AggregateExpr, BinaryExpr, MatrixSelector)):
            try:
                text = node.prettify() if hasattr(node, "prettify") else str(node)
            except Exception:  # noqa: BLE001
                text = str(node)
            text = text.strip()
            if text:
                out.append(text)

    walk_with_ancestors(expr, visit)
    return out


def find_repeated_subexpressions(expr: Any, *, min_length: int = 12) -> list[str]:
    """Return subexpression strings that appear more than once (conservative)."""
    counts: dict[str, int] = {}
    for text in collect_subtree_strings(expr):
        if len(text) < min_length:
            continue
        counts[text] = counts.get(text, 0) + 1
    return sorted(text for text, count in counts.items() if count >= 2)


def binary_join_info(expr: Any) -> list[str]:
    """Describe vector-matching joins found in the AST."""
    joins: list[str] = []

    def visit(node: Any, _ancestors: tuple[Any, ...]) -> None:
        if not isinstance(node, BinaryExpr):
            return
        modifier = getattr(node, "modifier", None)
        if modifier is None:
            return
        text = str(modifier)
        lowered = text.lower()
        if any(
            token in lowered
            for token in ("group_left", "group_right", "on (", "ignoring (")
        ):
            joins.append(f"{node.op} {text}".strip())

    walk_with_ancestors(expr, visit)
    return joins


def range_windows_minutes(expr: Any) -> list[tuple[str, float]]:
    """Return ``(label, minutes)`` for each matrix selector range."""
    windows: list[tuple[str, float]] = []

    def visit(node: Any, _ancestors: tuple[Any, ...]) -> None:
        if not isinstance(node, MatrixSelector):
            return
        seconds = node.range.total_seconds()
        try:
            import promql_parser

            label = promql_parser.display_duration(node.range)
        except Exception:  # noqa: BLE001
            label = f"{int(seconds)}s"
        windows.append((label, seconds / 60.0))

    walk_with_ancestors(expr, visit)
    return windows


def _is_unbounded_regex(matcher: Any) -> bool:
    if matcher.op != MatchOp.Re:
        return False
    return matcher.value in {".*", "^.*$", "(?s).*"}
