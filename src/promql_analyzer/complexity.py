"""Deterministic structural complexity scoring for PromQL queries.

The score represents structural complexity only. It does not estimate
Prometheus runtime cost or latency.
"""

from __future__ import annotations

from typing import Any

from promql_parser import BinaryExpr

from promql_analyzer.models import (
    AnalyzerConfig,
    ComplexityFactor,
    ComplexityLevel,
    ComplexityResult,
    ComplexityThresholds,
    ComplexityWeights,
    QueryStructure,
)
from promql_analyzer.rules.ast_utils import max_call_nesting_depth, walk_with_ancestors


def score_complexity(
    structure: QueryStructure,
    expr: Any,
    config: AnalyzerConfig | None = None,
) -> ComplexityResult:
    """Compute a transparent 0–100 structural complexity score."""
    cfg = config if config is not None else AnalyzerConfig()
    weights = cfg.complexity_weights
    factors = _collect_factors(structure, expr, weights)
    raw = sum(factor.contribution for factor in factors)
    score = max(0, min(100, raw))
    level = _level_for_score(score, cfg.complexity_thresholds)
    return ComplexityResult(score=score, level=level, factors=tuple(factors))


def _collect_factors(
    structure: QueryStructure,
    expr: Any,
    weights: ComplexityWeights,
) -> list[ComplexityFactor]:
    factors: list[ComplexityFactor] = []

    if weights.base > 0:
        factors.append(
            ComplexityFactor(
                name="base",
                contribution=weights.base,
                description="Base score for a non-empty PromQL expression",
            )
        )

    function_count = len(structure.functions)
    if function_count and weights.per_function:
        contribution = function_count * weights.per_function
        factors.append(
            ComplexityFactor(
                name="functions",
                contribution=contribution,
                description=(
                    f"{function_count} function/aggregation "
                    f"{'call' if function_count == 1 else 'calls'}"
                ),
            )
        )

    nesting_depth = max_call_nesting_depth(expr)
    nesting_levels = max(0, nesting_depth - 1)
    if nesting_levels and weights.per_nesting_level_above_1:
        contribution = nesting_levels * weights.per_nesting_level_above_1
        factors.append(
            ComplexityFactor(
                name="function_nesting",
                contribution=contribution,
                description=(
                    f"Nesting depth {nesting_depth} "
                    f"({nesting_levels} level{'s' if nesting_levels != 1 else ''} "
                    "above a single call)"
                ),
            )
        )

    matcher_count = len(structure.label_matchers)
    if matcher_count and weights.per_label_matcher:
        contribution = matcher_count * weights.per_label_matcher
        factors.append(
            ComplexityFactor(
                name="label_matchers",
                contribution=contribution,
                description=(
                    f"{matcher_count} label "
                    f"{'matcher' if matcher_count == 1 else 'matchers'}"
                ),
            )
        )

    regex_count = sum(
        1 for m in structure.label_matchers if m.operator in {"=~", "!~"}
    )
    if regex_count and weights.per_regex_matcher:
        contribution = regex_count * weights.per_regex_matcher
        factors.append(
            ComplexityFactor(
                name="regex_matchers",
                contribution=contribution,
                description=(
                    f"{regex_count} regex "
                    f"{'matcher' if regex_count == 1 else 'matchers'}"
                ),
            )
        )

    aggregation_count = len(structure.aggregations)
    if aggregation_count and weights.per_aggregation:
        contribution = aggregation_count * weights.per_aggregation
        factors.append(
            ComplexityFactor(
                name="aggregations",
                contribution=contribution,
                description=(
                    f"{aggregation_count} "
                    f"{'aggregation' if aggregation_count == 1 else 'aggregations'}"
                ),
            )
        )

    grouping_labels = sum(len(agg.grouping) for agg in structure.aggregations)
    if grouping_labels and weights.per_grouping_label:
        contribution = grouping_labels * weights.per_grouping_label
        factors.append(
            ComplexityFactor(
                name="grouping_labels",
                contribution=contribution,
                description=(
                    f"{grouping_labels} grouping "
                    f"{'label' if grouping_labels == 1 else 'labels'}"
                ),
            )
        )

    range_count = len(structure.range_vectors)
    if range_count and weights.per_range_vector:
        contribution = range_count * weights.per_range_vector
        factors.append(
            ComplexityFactor(
                name="range_vectors",
                contribution=contribution,
                description=(
                    f"{range_count} range "
                    f"{'vector' if range_count == 1 else 'vectors'}"
                ),
            )
        )

    binary_count = _count_binary_operators(expr)
    if binary_count and weights.per_binary_operator:
        contribution = binary_count * weights.per_binary_operator
        factors.append(
            ComplexityFactor(
                name="binary_operators",
                contribution=contribution,
                description=(
                    f"{binary_count} binary "
                    f"{'operator' if binary_count == 1 else 'operators'}"
                ),
            )
        )

    if structure.features.contains_subquery and weights.subquery:
        factors.append(
            ComplexityFactor(
                name="subquery",
                contribution=weights.subquery,
                description="Query contains a subquery",
            )
        )

    if structure.features.contains_offset and weights.offset:
        factors.append(
            ComplexityFactor(
                name="offset",
                contribution=weights.offset,
                description="Query uses an offset modifier",
            )
        )

    if structure.features.contains_at_modifier and weights.at_modifier:
        factors.append(
            ComplexityFactor(
                name="at_modifier",
                contribution=weights.at_modifier,
                description="Query uses an @ modifier",
            )
        )

    return factors


def _count_binary_operators(expr: Any) -> int:
    count = 0

    def visit(node: Any, _ancestors: tuple[Any, ...]) -> None:
        nonlocal count
        if isinstance(node, BinaryExpr):
            count += 1

    walk_with_ancestors(expr, visit)
    return count


def _level_for_score(score: int, thresholds: ComplexityThresholds) -> ComplexityLevel:
    if score <= thresholds.simple_max:
        return ComplexityLevel.SIMPLE
    if score <= thresholds.moderate_max:
        return ComplexityLevel.MODERATE
    if score <= thresholds.complex_max:
        return ComplexityLevel.COMPLEX
    return ComplexityLevel.VERY_COMPLEX
