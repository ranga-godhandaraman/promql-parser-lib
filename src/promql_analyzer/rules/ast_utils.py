"""Shared AST helpers for static-analysis rules."""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from typing import Any

from promql_parser import (
    AggregateExpr,
    BinaryExpr,
    Call,
    MatchOp,
    MatrixSelector,
    NumberLiteral,
    ParenExpr,
    StringLiteral,
    SubqueryExpr,
    UnaryExpr,
    VectorSelector,
)


def metric_name_from_selector(node: VectorSelector) -> str | None:
    """Return the metric name for a vector selector, if known."""
    if node.name:
        return node.name
    if node.matchers is None:
        return None
    for matcher in node.matchers.matchers:
        if matcher.name == "__name__" and matcher.op == MatchOp.Equal:
            return matcher.value
    return None


def walk_with_ancestors(
    node: Any,
    visitor: Callable[[Any, tuple[Any, ...]], None],
    ancestors: tuple[Any, ...] = (),
) -> None:
    """Depth-first walk calling ``visitor(node, ancestors)`` for each expr."""
    visitor(node, ancestors)
    child_ancestors = (*ancestors, node)

    if isinstance(node, VectorSelector):
        return
    if isinstance(node, MatrixSelector):
        walk_with_ancestors(node.vector_selector, visitor, child_ancestors)
        return
    if isinstance(node, Call):
        for arg in node.args:
            if _is_expr(arg):
                walk_with_ancestors(arg, visitor, child_ancestors)
        return
    if isinstance(node, AggregateExpr):
        if node.param is not None and _is_expr(node.param):
            walk_with_ancestors(node.param, visitor, child_ancestors)
        walk_with_ancestors(node.expr, visitor, child_ancestors)
        return
    if isinstance(node, BinaryExpr):
        walk_with_ancestors(node.lhs, visitor, child_ancestors)
        walk_with_ancestors(node.rhs, visitor, child_ancestors)
        return
    if isinstance(node, (UnaryExpr, ParenExpr, SubqueryExpr)):
        walk_with_ancestors(node.expr, visitor, child_ancestors)
        return


def max_call_nesting_depth(node: Any) -> int:
    """Return max nesting depth of Call and AggregateExpr nodes."""

    def _depth(n: Any) -> int:
        if isinstance(n, Call):
            child_depths = [_depth(arg) for arg in n.args if _is_expr(arg)]
            return 1 + (max(child_depths) if child_depths else 0)
        if isinstance(n, AggregateExpr):
            depths = [_depth(n.expr)]
            if n.param is not None and _is_expr(n.param):
                depths.append(_depth(n.param))
            return 1 + max(depths)
        if isinstance(n, MatrixSelector):
            return _depth(n.vector_selector)
        if isinstance(n, BinaryExpr):
            return max(_depth(n.lhs), _depth(n.rhs))
        if isinstance(n, (UnaryExpr, ParenExpr, SubqueryExpr)):
            return _depth(n.expr)
        return 0

    return _depth(node)


def ancestor_function_names(ancestors: tuple[Any, ...]) -> list[str]:
    """Return Call function names among ancestors (outermost first)."""
    names: list[str] = []
    for ancestor in ancestors:
        if isinstance(ancestor, Call):
            names.append(ancestor.func.name)
    return names


def timedelta_to_seconds(delta: timedelta) -> float:
    return delta.total_seconds()


def _is_expr(value: Any) -> bool:
    return isinstance(
        value,
        (
            AggregateExpr,
            BinaryExpr,
            Call,
            MatrixSelector,
            NumberLiteral,
            ParenExpr,
            StringLiteral,
            SubqueryExpr,
            UnaryExpr,
            VectorSelector,
        ),
    )
