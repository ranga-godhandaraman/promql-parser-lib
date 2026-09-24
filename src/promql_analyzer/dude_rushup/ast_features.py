"""AST-derived features used by the noise-risk rubric."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from promql_parser import (
    AggregateExpr,
    BinaryExpr,
    Call,
    MatrixSelector,
    NumberLiteral,
    ParenExpr,
    UnaryExpr,
    VectorSelector,
)

from promql_analyzer.rules.ast_utils import metric_name_from_selector, walk_with_ancestors

_RATE_FUNCS = frozenset({"rate", "increase", "irate", "delta"})
_COMPARE_OPS = frozenset({">", ">=", "<", "<=", "==", "!="})
_AGG_OPS = frozenset(
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


@dataclass(frozen=True)
class Comparison:
    """A numeric comparison extracted from the AST."""

    operator: str
    value: float


@dataclass(frozen=True)
class NoiseAstFeatures:
    """Structural facts needed by the 8-dimension noise rubric."""

    metrics: tuple[str, ...]
    functions: tuple[str, ...]
    aggregation_ops: tuple[str, ...]
    by_label_dims: tuple[str, ...]
    range_minutes: tuple[float, ...]
    range_labels: tuple[str, ...]
    comparisons: tuple[Comparison, ...]
    has_rate_or_increase: bool
    has_avg: bool
    has_min_or_max: bool


def extract_noise_features(expr: Any) -> NoiseAstFeatures:
    """Walk a PromQL AST and collect noise-scoring features."""
    metrics: list[str] = []
    seen_metrics: set[str] = set()
    functions: list[str] = []
    aggregation_ops: list[str] = []
    by_dims: set[str] = set()
    range_minutes: list[float] = []
    range_labels: list[str] = []
    comparisons: list[Comparison] = []
    has_rate = False
    has_avg = False
    has_min_max = False

    def _visit(node: Any, _ancestors: tuple[Any, ...]) -> None:
        nonlocal has_rate, has_avg, has_min_max

        if isinstance(node, VectorSelector):
            name = metric_name_from_selector(node)
            if name and name not in seen_metrics:
                seen_metrics.add(name)
                metrics.append(name)
            return

        if isinstance(node, MatrixSelector):
            minutes = _timedelta_minutes(node.range)
            label = _format_range_label(node.range)
            range_minutes.append(minutes)
            range_labels.append(label)
            return

        if isinstance(node, Call):
            fname = node.func.name
            functions.append(fname)
            if fname in _RATE_FUNCS:
                has_rate = True
            return

        if isinstance(node, AggregateExpr):
            op_name = _normalize_agg_op(node.op)
            aggregation_ops.append(op_name)
            functions.append(op_name)
            if op_name == "avg":
                has_avg = True
            if op_name in {"min", "max"}:
                has_min_max = True
            if node.modifier is not None:
                # Count distinct by-clause labels (blast radius / aggregation).
                grouping_type = str(node.modifier.type).rsplit(".", 1)[-1].lower()
                if grouping_type == "by":
                    for label in node.modifier.labels:
                        by_dims.add(label)
            return

        if isinstance(node, BinaryExpr):
            op_text = str(node.op).strip()
            if op_text in _COMPARE_OPS:
                value = _numeric_side(node.lhs, node.rhs)
                if value is not None:
                    comparisons.append(Comparison(operator=op_text, value=value))
            return

    walk_with_ancestors(expr, _visit)

    return NoiseAstFeatures(
        metrics=tuple(metrics),
        functions=tuple(functions),
        aggregation_ops=tuple(aggregation_ops),
        by_label_dims=tuple(sorted(by_dims)),
        range_minutes=tuple(range_minutes),
        range_labels=tuple(range_labels),
        comparisons=tuple(comparisons),
        has_rate_or_increase=has_rate,
        has_avg=has_avg,
        has_min_or_max=has_min_max,
    )


def parse_duration_minutes(text: str | None, *, default_minutes: float) -> float:
    """Parse Prometheus duration strings such as ``5m``, ``1h``, ``30s``."""
    if text is None or not str(text).strip():
        return default_minutes
    raw = str(text).strip().lower()
    # Support compound forms lightly: take the first number+unit.
    match = re.match(r"^(\d+(?:\.\d+)?)(ms|s|m|h|d)$", raw)
    if not match:
        return default_minutes
    value = float(match.group(1))
    unit = match.group(2)
    if unit == "ms":
        return value / 60000.0
    if unit == "s":
        return value / 60.0
    if unit == "m":
        return value
    if unit == "h":
        return value * 60.0
    if unit == "d":
        return value * 60.0 * 24.0
    return default_minutes


def metric_matches(metrics: tuple[str, ...], patterns: tuple[str, ...]) -> bool:
    """Return True if any metric name contains any configured pattern."""
    if not patterns or not metrics:
        return False
    for metric in metrics:
        for pattern in patterns:
            if pattern and pattern in metric:
                return True
    return False


def _normalize_agg_op(op: Any) -> str:
    if op is None:
        return "unknown"
    text = op if isinstance(op, str) else str(op)
    text = text.strip()
    if "." in text:
        text = text.rsplit(".", 1)[-1]
    text = text.lower()
    return text if text in _AGG_OPS else text


def _numeric_side(lhs: Any, rhs: Any) -> float | None:
    for side in (rhs, lhs):
        unwrapped = _unwrap(side)
        number = _number_value(unwrapped)
        if number is not None:
            return number
    return None


def _number_value(node: Any) -> float | None:
    if isinstance(node, NumberLiteral):
        return float(node.val)
    if hasattr(node, "value"):
        try:
            return float(node.value)
        except (TypeError, ValueError):
            return None
    return None


def _unwrap(node: Any) -> Any:
    while isinstance(node, ParenExpr):
        node = node.expr
    if isinstance(node, UnaryExpr):
        inner = _unwrap(node.expr)
        number = _number_value(inner)
        if number is not None and str(node.op).strip() == "-":

            class _Neg:
                val = -number
                value = -number

            return _Neg()
        return node
    return node


def _timedelta_minutes(delta: timedelta) -> float:
    return delta.total_seconds() / 60.0


def _format_range_label(delta: timedelta) -> str:
    total = delta.total_seconds()
    if total.is_integer():
        seconds = int(total)
        if seconds % 86400 == 0 and seconds >= 86400:
            return f"{seconds // 86400}d"
        if seconds % 3600 == 0 and seconds >= 3600:
            return f"{seconds // 3600}h"
        if seconds % 60 == 0 and seconds >= 60:
            return f"{seconds // 60}m"
        return f"{seconds}s"
    return f"{total}s"
