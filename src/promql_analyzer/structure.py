"""Structural extraction from a PromQL AST.

Traverses the ``promql-parser`` expression tree recursively so nested
PromQL is understood without regex-based parsing.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import promql_parser
from promql_parser import (
    AggModifierType,
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

from promql_analyzer.models import (
    Aggregation,
    LabelMatcher,
    QueryFeatures,
    QueryStructure,
)

# Aggregation operator names as they appear in PromQL.
_AGGREGATION_OPS = frozenset(
    {
        "sum",
        "avg",
        "min",
        "max",
        "count",
        "group",
        "stddev",
        "stdvar",
        "topk",
        "bottomk",
        "count_values",
        "quantile",
    }
)


def extract_structure(expr: Any) -> QueryStructure:
    """Extract structural information from a parsed PromQL expression."""
    metrics: list[str] = []
    functions: list[str] = []
    aggregations: list[Aggregation] = []
    label_matchers: list[LabelMatcher] = []
    range_vectors: list[str] = []

    seen_metrics: set[str] = set()
    seen_matchers: set[tuple[str, str, str]] = set()
    seen_ranges: set[str] = set()

    contains_regex = False
    contains_binary = False
    contains_aggregation = False
    contains_subquery = False
    contains_offset = False
    contains_at = False
    max_call_depth = 0

    def _visit(node: Any, call_depth: int) -> None:
        nonlocal contains_regex, contains_binary, contains_aggregation
        nonlocal contains_subquery, contains_offset, contains_at, max_call_depth

        if isinstance(node, VectorSelector):
            _collect_vector_selector(
                node,
                metrics,
                seen_metrics,
                label_matchers,
                seen_matchers,
            )
            if _has_regex_matcher(node):
                contains_regex = True
            if node.offset is not None:
                contains_offset = True
            if node.at is not None:
                contains_at = True
            return

        if isinstance(node, MatrixSelector):
            duration = _format_duration(node.range)
            if duration not in seen_ranges:
                seen_ranges.add(duration)
                range_vectors.append(duration)
            _visit(node.vector_selector, call_depth)
            return

        if isinstance(node, Call):
            depth = call_depth + 1
            max_call_depth = max(max_call_depth, depth)
            functions.append(node.func.name)
            for arg in node.args:
                if _is_expr(arg):
                    _visit(arg, depth)
            return

        if isinstance(node, AggregateExpr):
            contains_aggregation = True
            depth = call_depth + 1
            max_call_depth = max(max_call_depth, depth)
            op_name = _normalize_op_name(node.op)
            functions.append(op_name)
            aggregations.append(_aggregation_from_expr(node, op_name))
            if node.param is not None and _is_expr(node.param):
                _visit(node.param, depth)
            _visit(node.expr, depth)
            return

        if isinstance(node, BinaryExpr):
            contains_binary = True
            _visit(node.lhs, call_depth)
            _visit(node.rhs, call_depth)
            return

        if isinstance(node, UnaryExpr):
            _visit(node.expr, call_depth)
            return

        if isinstance(node, ParenExpr):
            _visit(node.expr, call_depth)
            return

        if isinstance(node, SubqueryExpr):
            contains_subquery = True
            if node.range is not None:
                duration = _format_duration(node.range)
                if node.step is not None:
                    duration = f"{duration}:{_format_duration(node.step)}"
                if duration not in seen_ranges:
                    seen_ranges.add(duration)
                    range_vectors.append(duration)
            if node.offset is not None:
                contains_offset = True
            if node.at is not None:
                contains_at = True
            _visit(node.expr, call_depth)
            return

        # Literals and unknown nodes: nothing to extract.

    _visit(expr, call_depth=0)

    return QueryStructure(
        metrics=tuple(metrics),
        functions=tuple(functions),
        aggregations=tuple(aggregations),
        label_matchers=tuple(label_matchers),
        range_vectors=tuple(range_vectors),
        features=QueryFeatures(
            contains_regex_matcher=contains_regex,
            contains_binary_operator=contains_binary,
            contains_aggregation=contains_aggregation,
            contains_nested_function=max_call_depth >= 2,
            contains_subquery=contains_subquery,
            contains_offset=contains_offset,
            contains_at_modifier=contains_at,
        ),
    )


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


def _collect_vector_selector(
    node: VectorSelector,
    metrics: list[str],
    seen_metrics: set[str],
    label_matchers: list[LabelMatcher],
    seen_matchers: set[tuple[str, str, str]],
) -> None:
    metric_name = node.name
    matchers = list(node.matchers.matchers) if node.matchers is not None else []

    if metric_name is None:
        for matcher in matchers:
            if matcher.name == "__name__" and _is_equal_op(matcher.op):
                metric_name = matcher.value
                break

    if metric_name and metric_name not in seen_metrics:
        seen_metrics.add(metric_name)
        metrics.append(metric_name)

    for matcher in matchers:
        # Skip the synthetic __name__ matcher when it only encodes the metric.
        if matcher.name == "__name__" and _is_equal_op(matcher.op):
            continue
        operator = _matcher_operator(matcher.op)
        key = (matcher.name, operator, matcher.value)
        if key in seen_matchers:
            continue
        seen_matchers.add(key)
        label_matchers.append(
            LabelMatcher(label=matcher.name, operator=operator, value=matcher.value)
        )


def _is_equal_op(op: Any) -> bool:
    # MatchOp values are not hashable in promql-parser; compare with ==.
    return op == MatchOp.Equal


def _matcher_operator(op: Any) -> str:
    if op == MatchOp.Equal:
        return "="
    if op == MatchOp.NotEqual:
        return "!="
    if op == MatchOp.Re:
        return "=~"
    if op == MatchOp.NotRe:
        return "!~"
    text = str(op).rsplit(".", 1)[-1].lower()
    return {
        "equal": "=",
        "notequal": "!=",
        "re": "=~",
        "notre": "!~",
    }.get(text, str(op))


def _has_regex_matcher(node: VectorSelector) -> bool:
    if node.matchers is None:
        return False
    return any(m.op == MatchOp.Re or m.op == MatchOp.NotRe for m in node.matchers.matchers)


def _aggregation_from_expr(node: AggregateExpr, op_name: str) -> Aggregation:
    grouping: tuple[str, ...] = ()
    grouping_type: str | None = None
    modifier = node.modifier
    if modifier is not None:
        grouping = tuple(modifier.labels)
        if modifier.type == AggModifierType.By:
            grouping_type = "by"
        elif modifier.type == AggModifierType.Without:
            grouping_type = "without"
        else:
            grouping_type = str(modifier.type).rsplit(".", 1)[-1].lower()
    return Aggregation(operator=op_name, grouping=grouping, grouping_type=grouping_type)


def _normalize_op_name(op: Any) -> str:
    """Normalize parser operator tokens to PromQL lowercase names."""
    if op is None:
        return "unknown"
    text = op if isinstance(op, str) else str(op)
    text = text.strip()
    if "." in text:
        text = text.rsplit(".", 1)[-1]
    text = text.lower()
    if text in _AGGREGATION_OPS:
        return text
    return text


def _format_duration(delta: timedelta) -> str:
    """Format a duration using Prometheus-style units when possible."""
    try:
        return promql_parser.display_duration(delta)
    except Exception:  # noqa: BLE001
        total = int(delta.total_seconds())
        if total % 3600 == 0 and total >= 3600:
            return f"{total // 3600}h"
        if total % 60 == 0 and total >= 60:
            return f"{total // 60}m"
        return f"{total}s"
