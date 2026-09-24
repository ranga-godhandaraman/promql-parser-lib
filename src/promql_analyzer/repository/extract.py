"""Extract alert/recording/condition rules from loaded YAML documents.

Uses the shared PromQL discovery helpers so expressions are found under
``expr``, ``condition``, ``query``, ``promql``, and similar fields — not only
classic Prometheus ``expr``.
"""

from __future__ import annotations

from typing import Any

from promql_analyzer.discovery import (
    KNOWN_PROMQL_KEYS,
    ExtractedQuery,
    discover_promql_queries,
)
from promql_analyzer.repository.models import RuleRecord


def extract_rule_records(document: Any, *, file_path: str) -> list[RuleRecord]:
    """Extract alert/recording/condition rules from a parsed YAML document."""
    records: list[RuleRecord] = []
    covered_paths: set[str] = set()
    _walk(
        document,
        file_path=file_path,
        group_name=None,
        path="",
        out=records,
        covered_paths=covered_paths,
    )

    # Catch PromQL in unfamiliar keys that the rule-object walk skipped.
    for query in discover_promql_queries(document):
        if query.location in covered_paths:
            continue
        if any(
            r.expr == query.expr and _paths_overlap(r.location, query.location)
            for r in records
            if r.expr
        ):
            continue
        records.append(_record_from_discovered(query, file_path=file_path))
        covered_paths.add(query.location)

    return records


def looks_like_prometheus_rules(document: Any) -> bool:
    """Return True if the document appears to contain PromQL rule/condition objects."""
    return bool(extract_rule_records(document, file_path=""))


def _walk(
    node: Any,
    *,
    file_path: str,
    group_name: str | None,
    path: str,
    out: list[RuleRecord],
    covered_paths: set[str],
) -> None:
    if isinstance(node, dict):
        current_group = group_name
        if isinstance(node.get("name"), str) and "rules" in node:
            current_group = node["name"].strip() or group_name

        if _is_rule_object(node):
            promql_key = _promql_field_key(node)
            if promql_key is not None:
                field_path = f"{path}.{promql_key}" if path else promql_key
                covered_paths.add(field_path)
            out.append(
                _rule_from_object(
                    node,
                    file_path=file_path,
                    group_name=current_group,
                    path=path,
                    promql_key=promql_key,
                )
            )
            # Do not recurse into rule object children for nested fake rules.
            return

        for key, value in node.items():
            child_path = f"{path}.{key}" if path else str(key)
            _walk(
                value,
                file_path=file_path,
                group_name=current_group,
                path=child_path,
                out=out,
                covered_paths=covered_paths,
            )
        return

    if isinstance(node, list):
        for index, item in enumerate(node):
            child_path = f"{path}[{index}]" if path else f"[{index}]"
            _walk(
                item,
                file_path=file_path,
                group_name=group_name,
                path=child_path,
                out=out,
                covered_paths=covered_paths,
            )


def _is_rule_object(node: dict[str, Any]) -> bool:
    """Return True for alert/recording rules or documents with a known PromQL field."""
    if "alert" in node or "record" in node:
        return True
    return _promql_field_key(node) is not None


def _promql_field_key(node: dict[str, Any]) -> str | None:
    """Return the preferred key that holds PromQL in ``node``, if any."""
    # Prefer classic Prometheus ``expr`` when present.
    if "expr" in node:
        return "expr"
    for key in node:
        if isinstance(key, str) and key.lower() in KNOWN_PROMQL_KEYS:
            return key
    return None


def _rule_from_object(
    node: dict[str, Any],
    *,
    file_path: str,
    group_name: str | None,
    path: str,
    promql_key: str | None,
) -> RuleRecord:
    name: str | None = None
    kind = "unknown"
    name_empty = False

    if "alert" in node:
        kind = "alert"
        raw_name = node.get("alert")
        if isinstance(raw_name, str) and raw_name.strip():
            name = raw_name.strip()
        else:
            name_empty = True
    elif "record" in node:
        kind = "record"
        raw_name = node.get("record")
        if isinstance(raw_name, str) and raw_name.strip():
            name = raw_name.strip()
        else:
            name_empty = True
    else:
        kind = "condition"
        name = _condition_name(node)

    # Any known PromQL field counts — not only classic ``expr``.
    expr_present = promql_key is not None
    expr_value = node.get(promql_key) if promql_key is not None else None
    expr: str | None = None
    expr_empty = False
    expr_non_string = False
    if promql_key is not None:
        if isinstance(expr_value, str):
            if expr_value.strip():
                expr = expr_value.strip()
            else:
                expr_empty = True
        else:
            expr_non_string = True

    for_present = "for" in node
    for_value = node.get("for") if for_present else None
    for_text: str | None = None
    for_malformed = False
    if for_present:
        if isinstance(for_value, str) and for_value.strip():
            for_text = for_value.strip()
        elif for_value is None or (isinstance(for_value, str) and not for_value.strip()):
            for_malformed = True
        else:
            for_malformed = True

    labels_value = node.get("labels") if "labels" in node else None
    labels_malformed = "labels" in node and not isinstance(labels_value, dict)
    labels = _mapping_pairs(labels_value) if isinstance(labels_value, dict) else ()

    annotations_value = node.get("annotations") if "annotations" in node else None
    annotations_malformed = "annotations" in node and not isinstance(
        annotations_value, dict
    )
    annotations = (
        _mapping_pairs(annotations_value)
        if isinstance(annotations_value, dict)
        else ()
    )

    location = path or kind
    if name:
        location = f"{location}.{kind}={name}" if path else f"{kind}={name}"

    return RuleRecord(
        file_path=file_path,
        kind=kind,
        name=name,
        expr=expr,
        group_name=group_name,
        location=location,
        labels=labels,
        annotations=annotations,
        for_duration=for_text,
        expr_present=expr_present,
        expr_empty=expr_empty,
        expr_non_string=expr_non_string,
        labels_malformed=labels_malformed,
        annotations_malformed=annotations_malformed,
        name_empty=name_empty,
        for_malformed=for_malformed,
    )


def _record_from_discovered(query: ExtractedQuery, *, file_path: str) -> RuleRecord:
    kind = query.rule_kind or "condition"
    return RuleRecord(
        file_path=file_path,
        kind=kind,
        name=query.rule_name,
        expr=query.expr,
        location=query.location,
        expr_present=True,
    )


def _paths_overlap(rule_location: str, query_location: str) -> bool:
    """Return True when a rule location and discovery path refer to the same object."""
    if not rule_location or not query_location:
        return False
    if rule_location == query_location:
        return True
    # Rule locations often append ``.alert=Name`` after the object path.
    base = rule_location.split(".alert=", 1)[0].split(".record=", 1)[0].split(
        ".condition=", 1
    )[0]
    return query_location == base or query_location.startswith(base + ".")


def _condition_name(node: dict[str, Any]) -> str | None:
    context = node.get("context")
    if isinstance(context, dict):
        for key in ("tip_situation", "name", "id"):
            raw = context.get(key)
            if isinstance(raw, str) and raw.strip():
                return raw.strip()
    for key in ("name", "title", "id"):
        raw = node.get(key)
        if isinstance(raw, str) and raw.strip():
            return raw.strip()
    return None


def _mapping_pairs(value: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    pairs: list[tuple[str, str]] = []
    for key, item in value.items():
        if not isinstance(key, str):
            continue
        if item is None:
            pairs.append((key, ""))
            continue
        if isinstance(item, (str, int, float, bool)):
            pairs.append((key, str(item)))
        else:
            # Nested/non-scalar label values are preserved as a marker string
            # so broken() can still see the key existed.
            pairs.append((key, f"<{type(item).__name__}>"))
    return tuple(pairs)
