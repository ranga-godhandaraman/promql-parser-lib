"""Deterministic PromQL explanation engine.

Explanations are built from the parsed AST. Metric meaning is never invented
beyond the literal metric name and well-known function semantics.
"""

from __future__ import annotations

from typing import Any

import promql_parser
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

from promql_analyzer.models import Explanation
from promql_analyzer.rules.ast_utils import metric_name_from_selector

_MATCHER_VERBS = {
    "=": "equals",
    "!=": "does not equal",
    "=~": "matches the regular expression",
    "!~": "does not match the regular expression",
}

_AGGREGATION_VERBS = {
    "sum": "sums",
    "avg": "averages",
    "min": "takes the minimum of",
    "max": "takes the maximum of",
    "count": "counts",
    "group": "groups",
    "stddev": "computes the standard deviation of",
    "stdvar": "computes the standard variance of",
    "topk": "selects the top-k series from",
    "bottomk": "selects the bottom-k series from",
    "count_values": "counts distinct values in",
    "quantile": "computes a quantile over",
}

_FUNCTION_GLOSSES = {
    "rate": "calculates the per-second average rate of increase of",
    "irate": "calculates the per-second instant rate of increase of",
    "increase": "calculates the increase of",
    "delta": "calculates the difference of",
    "idelta": "calculates the instant difference of",
    "deriv": "calculates the derivative of",
    "predict_linear": "predicts a linear future value of",
    "histogram_quantile": "calculates a quantile from histogram buckets of",
    "abs": "takes the absolute value of",
    "ceil": "rounds up",
    "floor": "rounds down",
    "round": "rounds",
    "clamp_min": "clamps the minimum of",
    "clamp_max": "clamps the maximum of",
    "clamp": "clamps the values of",
    "sgn": "takes the sign of",
    "ln": "takes the natural logarithm of",
    "log2": "takes the base-2 logarithm of",
    "log10": "takes the base-10 logarithm of",
    "exp": "raises e to the power of",
    "sqrt": "takes the square root of",
    "timestamp": "returns the timestamp of",
    "time": "returns the evaluation timestamp",
    "vector": "creates a vector from",
    "scalar": "converts to a scalar",
    "label_replace": "replaces a label on",
    "label_join": "joins labels on",
    "sort": "sorts",
    "sort_desc": "sorts in descending order",
    "absent": "checks for absence of",
    "absent_over_time": "checks for absence over time of",
}


def explain_query(expr: Any) -> Explanation:
    """Build concise and detailed explanations for ``expr``."""
    return Explanation(
        concise=_compose_concise(expr),
        detailed=_compose_detailed(expr),
    )


def _unwrap(node: Any) -> Any:
    while isinstance(node, ParenExpr):
        node = node.expr
    return node


def _compose_concise(expr: Any) -> str:
    node = _unwrap(expr)
    body = _explain_node(node, detailed=False)
    if not body:
        return "This query could not be explained."

    if isinstance(node, (VectorSelector, MatrixSelector)):
        sentence = f"This query selects {body}."
    elif isinstance(node, NumberLiteral):
        sentence = f"This query evaluates to {body}."
    elif isinstance(node, StringLiteral):
        sentence = f"This query evaluates to {body}."
    else:
        sentence = f"This query {body}."

    return _ensure_period(sentence)


def _compose_detailed(expr: Any) -> str:
    sentences = _detailed_sentences(_unwrap(expr))
    if not sentences:
        return "This query could not be explained."
    return " ".join(_ensure_period(s) for s in sentences if s.strip())


def _ensure_period(text: str) -> str:
    text = text.strip()
    if not text.endswith("."):
        return text + "."
    return text


def _explain_node(node: Any, *, detailed: bool) -> str:
    node = _unwrap(node)

    if isinstance(node, NumberLiteral):
        return f"the scalar value {node.val:g}"

    if isinstance(node, StringLiteral):
        return f'the string "{node.val}"'

    if isinstance(node, VectorSelector):
        return _explain_vector_selector(node, detailed=detailed)

    if isinstance(node, MatrixSelector):
        inner = _explain_node(node.vector_selector, detailed=detailed)
        range_text = _format_duration(node.range)
        return f"{inner} over the previous {range_text}"

    if isinstance(node, Call):
        return _explain_call(node, detailed=detailed)

    if isinstance(node, AggregateExpr):
        return _explain_aggregation(node, detailed=detailed)

    if isinstance(node, BinaryExpr):
        left = _explain_node(node.lhs, detailed=detailed)
        right = _explain_node(node.rhs, detailed=detailed)
        op = str(node.op).strip()
        return f"combines ({left}) {op} ({right})"

    if isinstance(node, UnaryExpr):
        inner = _explain_node(node.expr, detailed=detailed)
        return f"applies a unary operator to ({inner})"

    if isinstance(node, SubqueryExpr):
        inner = _explain_node(node.expr, detailed=detailed)
        range_text = (
            _format_duration(node.range) if node.range is not None else "a range"
        )
        step_text = ""
        if node.step is not None:
            step_text = f" with step {_format_duration(node.step)}"
        return f"evaluates a subquery of ({inner}) over {range_text}{step_text}"

    return "evaluates a PromQL expression"


def _explain_vector_selector(node: VectorSelector, *, detailed: bool) -> str:
    name = metric_name_from_selector(node)
    if name:
        base = f"the metric named `{name}`"
    else:
        base = "matching time series"

    matchers = _matcher_phrases(node, detailed=detailed)
    if matchers:
        base = f"{base} for series where {_join_phrases(matchers)}"

    extras: list[str] = []
    if node.offset is not None:
        extras.append(f"offset by {_format_duration(node.offset)}")
    if node.at is not None:
        extras.append("evaluated at a specific time (@ modifier)")
    if extras:
        base = f"{base}, {', '.join(extras)}"
    return base


def _matcher_phrases(node: VectorSelector, *, detailed: bool) -> list[str]:
    if node.matchers is None:
        return []
    phrases: list[str] = []
    for matcher in node.matchers.matchers:
        if matcher.name == "__name__" and matcher.op == MatchOp.Equal:
            continue
        op = _matcher_operator(matcher.op)
        verb = _MATCHER_VERBS.get(op, f"matches with operator {op}")
        if detailed:
            phrases.append(f"the `{matcher.name}` label {verb} `{matcher.value}`")
        else:
            phrases.append(f"`{matcher.name}` {verb} `{matcher.value}`")
    return phrases


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


def _explain_call(node: Call, *, detailed: bool) -> str:
    name = node.func.name

    if name in {"rate", "irate", "increase"} and node.args:
        arg = node.args[0]
        if isinstance(arg, MatrixSelector):
            metric_part = _explain_node(arg.vector_selector, detailed=detailed)
            range_text = _format_duration(arg.range)
            if name == "rate":
                return (
                    "calculates the per-second average rate of increase of "
                    f"{metric_part} over the previous {range_text}"
                )
            if name == "irate":
                return (
                    "calculates the per-second instant rate of increase of "
                    f"{metric_part} over the previous {range_text}"
                )
            return (
                f"calculates the increase of {metric_part} over the previous "
                f"{range_text}"
            )

    if name == "histogram_quantile" and len(node.args) >= 2:
        quantile = _quantile_label(node.args[0])
        buckets = _explain_node(node.args[1], detailed=detailed)
        return (
            f"calculates the {quantile} quantile from histogram buckets produced by "
            f"({buckets})"
        )

    gloss = _FUNCTION_GLOSSES.get(name)
    expr_args = [a for a in node.args if _is_expr_like(a)]
    if not expr_args:
        if gloss:
            return f"{gloss} its arguments"
        return f"calls the `{name}` function"

    primary = _explain_node(expr_args[0], detailed=detailed)
    if gloss:
        phrase = f"{gloss} ({primary})"
    else:
        phrase = f"applies the `{name}` function to ({primary})"

    if detailed and len(expr_args) > 1:
        others = ", ".join(_explain_node(a, detailed=True) for a in expr_args[1:])
        phrase = f"{phrase}, with additional arguments: {others}"
    return phrase


def _explain_aggregation(node: AggregateExpr, *, detailed: bool) -> str:
    op_name = _agg_op_name(node)
    verb = _AGGREGATION_VERBS.get(op_name, f"aggregates with `{op_name}` over")
    inner = _explain_node(node.expr, detailed=detailed)
    phrase = f"{verb} ({inner})"

    modifier = node.modifier
    if modifier is not None and modifier.labels:
        labels = ", ".join(f"`{label}`" for label in modifier.labels)
        type_name = str(modifier.type).rsplit(".", 1)[-1].lower()
        if type_name == "by":
            if len(modifier.labels) == 1:
                phrase += f" while keeping separate results for each {labels}"
            else:
                phrase += (
                    " while keeping separate results for each combination of "
                    f"{labels}"
                )
        elif type_name == "without":
            phrase += f" while removing the labels {labels} from the result"
        else:
            phrase += f" with grouping ({type_name}: {labels})"
    return phrase


def _agg_op_name(node: AggregateExpr) -> str:
    op_name = str(node.op).strip().lower()
    if "." in op_name:
        op_name = op_name.rsplit(".", 1)[-1]
    return op_name


def _grouping_clause(node: AggregateExpr) -> str:
    modifier = node.modifier
    if modifier is None or not modifier.labels:
        return ""
    labels = ", ".join(f"`{label}`" for label in modifier.labels)
    type_name = str(modifier.type).rsplit(".", 1)[-1].lower()
    if type_name == "by":
        if len(modifier.labels) == 1:
            return f" while keeping separate results for each {labels}"
        return (
            " while keeping separate results for each combination of "
            f"{labels}"
        )
    if type_name == "without":
        return f" while removing the labels {labels} from the result"
    return f" with grouping ({type_name}: {labels})"


def _detailed_sentences(node: Any) -> list[str]:
    node = _unwrap(node)

    if isinstance(node, AggregateExpr):
        sentences = _detailed_sentences(node.expr)
        op_name = _agg_op_name(node)
        verb = _AGGREGATION_VERBS.get(op_name, f"aggregates with `{op_name}`")
        grouping = _grouping_clause(node)
        if op_name == "sum":
            sentences.append(f"It then sums the resulting series{grouping}")
        else:
            sentences.append(f"It then {verb} the resulting series{grouping}")
        return sentences

    if isinstance(node, Call):
        name = node.func.name
        if name in {"rate", "irate", "increase"} and node.args:
            arg = node.args[0]
            if isinstance(arg, MatrixSelector):
                metric = _explain_vector_selector(arg.vector_selector, detailed=True)
                range_text = _format_duration(arg.range)
                if name == "rate":
                    action = "calculates the per-second average rate of increase"
                elif name == "irate":
                    action = "calculates the per-second instant rate of increase"
                else:
                    action = "calculates the increase"
                return [
                    f"This query {action} of {metric} over the previous {range_text}"
                ]

        if name == "histogram_quantile" and len(node.args) >= 2:
            inner = _detailed_sentences(node.args[1])
            quantile = _quantile_label(node.args[0])
            inner.append(
                f"It then calculates the {quantile} quantile from those histogram buckets"
            )
            return inner

        expr_args = [a for a in node.args if _is_expr_like(a)]
        if expr_args:
            sentences = _detailed_sentences(expr_args[0])
            gloss = _FUNCTION_GLOSSES.get(name, f"applies the `{name}` function to")
            sentences.append(f"It then {gloss} the resulting values")
            return sentences
        return [f"This query calls the `{name}` function"]

    if isinstance(node, BinaryExpr):
        left = _detailed_sentences(node.lhs)
        right_brief = _explain_node(node.rhs, detailed=True)
        op = str(node.op).strip()
        left.append(f"It then combines that result {op} ({right_brief})")
        return left

    if isinstance(node, MatrixSelector):
        metric = _explain_vector_selector(node.vector_selector, detailed=True)
        range_text = _format_duration(node.range)
        return [f"This query selects {metric} over the previous {range_text}"]

    if isinstance(node, VectorSelector):
        metric = _explain_vector_selector(node, detailed=True)
        return [f"This query selects {metric}"]

    if isinstance(node, SubqueryExpr):
        inner = _detailed_sentences(node.expr)
        range_text = (
            _format_duration(node.range) if node.range is not None else "a range"
        )
        step = (
            f" with step {_format_duration(node.step)}"
            if node.step is not None
            else ""
        )
        inner.append(
            f"It then evaluates that expression as a subquery over {range_text}{step}"
        )
        return inner

    if isinstance(node, UnaryExpr):
        return _detailed_sentences(node.expr)

    if isinstance(node, NumberLiteral):
        return [f"This query evaluates to the scalar value {node.val:g}"]

    return [f"This query {_explain_node(node, detailed=True)}"]


def _quantile_label(node: Any) -> str:
    if isinstance(node, NumberLiteral):
        return f"{node.val:g}"
    return _explain_node(node, detailed=False)


def _join_phrases(phrases: list[str]) -> str:
    if len(phrases) == 1:
        return phrases[0]
    if len(phrases) == 2:
        return f"{phrases[0]} and {phrases[1]}"
    return ", ".join(phrases[:-1]) + f", and {phrases[-1]}"


def _format_duration(delta: Any) -> str:
    try:
        return promql_parser.display_duration(delta)
    except Exception:  # noqa: BLE001
        seconds = int(delta.total_seconds())
        if seconds % 3600 == 0 and seconds >= 3600:
            return f"{seconds // 3600}h"
        if seconds % 60 == 0 and seconds >= 60:
            return f"{seconds // 60}m"
        return f"{seconds}s"


def _is_expr_like(value: Any) -> bool:
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
