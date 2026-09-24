"""Repository-level inventory and conservative duplicate detection."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass

from promql_analyzer.dude_rushup._base import make_finding
from promql_analyzer.models import Finding, Severity
from promql_analyzer.repository.models import RuleRecord

_WHITESPACE_RE = re.compile(r"\s+")


@dataclass(frozen=True)
class RepositoryInventory:
    """Aggregate inventory facts for a scanned rule repository."""

    alert_count: int = 0
    recording_rule_count: int = 0
    unique_alert_names: int = 0
    duplicate_alert_name_count: int = 0
    duplicate_expression_count: int = 0
    near_duplicate_count: int = 0
    severity_distribution: tuple[tuple[str, int], ...] = ()
    missing_ownership_count: int = 0
    missing_runbook_count: int = 0


def normalize_expr(expr: str | None) -> str:
    """Normalize PromQL text for exact duplicate comparison."""
    if not expr:
        return ""
    return _WHITESPACE_RE.sub(" ", expr.strip())


def build_inventory(
    alerts: tuple[RuleRecord, ...] | list[RuleRecord],
    recording_rules: tuple[RuleRecord, ...] | list[RuleRecord],
    *,
    ownership_keys: tuple[str, ...] = ("owner", "team"),
    runbook_keys: tuple[str, ...] = ("runbook_url", "runbook"),
) -> RepositoryInventory:
    """Compute inventory statistics for discovered rules."""
    alert_list = list(alerts)
    record_list = list(recording_rules)

    name_counts: Counter[str] = Counter(
        a.name for a in alert_list if a.name
    )
    duplicate_names = sum(1 for _name, count in name_counts.items() if count > 1)

    expr_counts: Counter[str] = Counter(
        normalize_expr(a.expr) for a in alert_list if normalize_expr(a.expr)
    )
    duplicate_exprs = sum(1 for _expr, count in expr_counts.items() if count > 1)

    near = _count_near_duplicates(alert_list)

    severity_counts: Counter[str] = Counter()
    for alert in alert_list:
        labels = dict(alert.labels)
        sev = labels.get("severity") or labels.get("Severity")
        severity_counts[sev if sev else "(none)"] += 1

    missing_ownership = 0
    missing_runbook = 0
    for alert in alert_list:
        label_keys = {k.lower() for k, _ in alert.labels}
        ann_keys = {k.lower() for k, _ in alert.annotations}
        if ownership_keys and not any(k.lower() in label_keys for k in ownership_keys):
            missing_ownership += 1
        if runbook_keys and not any(k.lower() in ann_keys for k in runbook_keys):
            missing_runbook += 1

    return RepositoryInventory(
        alert_count=len(alert_list),
        recording_rule_count=len(record_list),
        unique_alert_names=len(name_counts),
        duplicate_alert_name_count=duplicate_names,
        duplicate_expression_count=duplicate_exprs,
        near_duplicate_count=near,
        severity_distribution=tuple(sorted(severity_counts.items())),
        missing_ownership_count=missing_ownership,
        missing_runbook_count=missing_runbook,
    )


def repository_findings(
    alerts: tuple[RuleRecord, ...] | list[RuleRecord],
    *,
    check_duplicate_names: bool = True,
    check_duplicate_exprs: bool = True,
    check_near_duplicates: bool = True,
    category: str = "repository",
    rule_id_prefix: str = "REPO",
) -> list[Finding]:
    """Emit conservative repository-level duplicate findings."""
    findings: list[Finding] = []
    alert_list = [a for a in alerts if a.is_alert_like]

    if check_duplicate_names:
        by_name: dict[str, list[RuleRecord]] = defaultdict(list)
        for alert in alert_list:
            if alert.name:
                by_name[alert.name].append(alert)
        for name, group in sorted(by_name.items()):
            if len(group) < 2:
                continue
            locations = ", ".join(f"{r.file_path}" for r in group)
            findings.append(
                make_finding(
                    rule_id=f"{rule_id_prefix}001",
                    severity=Severity.WARNING,
                    message=f"Duplicate alert name {name!r} across {len(group)} rules",
                    explanation=(
                        "Multiple alert rules share the same alert name. "
                        "Prometheus allows this across files, but it often causes "
                        "routing and silence ambiguity."
                    ),
                    suggestion="Rename alerts so each alert identity is unique.",
                    category=category,
                    file_path=group[0].file_path,
                    rule_name=name,
                    evidence=(f"locations={locations}", f"count={len(group)}"),
                )
            )

    if check_duplicate_exprs:
        by_expr: dict[str, list[RuleRecord]] = defaultdict(list)
        for alert in alert_list:
            key = normalize_expr(alert.expr)
            if key:
                by_expr[key].append(alert)
        for expr, group in by_expr.items():
            if len(group) < 2:
                continue
            names = ", ".join(sorted({r.name or "?" for r in group}))
            findings.append(
                make_finding(
                    rule_id=f"{rule_id_prefix}002",
                    severity=Severity.INFO,
                    message=(
                        f"Duplicate alert expression shared by {len(group)} alerts"
                    ),
                    explanation=(
                        "Two or more alerts use the same PromQL expression "
                        "(whitespace-normalized). This may be intentional, but "
                        "often indicates copy/paste sprawl."
                    ),
                    suggestion="Consolidate duplicate alerts or differentiate expressions.",
                    category=category,
                    file_path=group[0].file_path,
                    rule_name=group[0].name,
                    evidence=(f"expr={expr}", f"alerts={names}"),
                )
            )

    if check_near_duplicates:
        findings.extend(_near_duplicate_findings(alert_list, rule_id_prefix, category))

    return findings


def _count_near_duplicates(alerts: list[RuleRecord]) -> int:
    pairs = 0
    seen: set[tuple[str, str]] = set()
    for left, right, reason in _near_duplicate_pairs(alerts):
        key = tuple(
            sorted(
                [
                    f"{left.file_path}:{left.name or ''}",
                    f"{right.file_path}:{right.name or ''}",
                ]
            )
        )
        marker = (f"{key[0]}|{key[1]}", reason)
        if marker in seen:
            continue
        seen.add(marker)
        pairs += 1
    return pairs


def _near_duplicate_findings(
    alerts: list[RuleRecord],
    rule_id_prefix: str,
    category: str,
) -> list[Finding]:
    findings: list[Finding] = []
    emitted: set[tuple[str, str]] = set()
    for left, right, reason in _near_duplicate_pairs(alerts):
        key = tuple(
            sorted(
                [
                    f"{left.file_path}:{left.name}",
                    f"{right.file_path}:{right.name}",
                ]
            )
        )
        if key in emitted:
            continue
        emitted.add(key)
        findings.append(
            make_finding(
                rule_id=f"{rule_id_prefix}003",
                severity=Severity.INFO,
                message=(
                    f"Near-duplicate alerts {left.name!r} and {right.name!r}"
                ),
                explanation=(
                    "Alerts look nearly identical under a conservative check "
                    f"({reason}). This is a static hint, not proof they are redundant."
                ),
                suggestion="Review whether both alerts are needed.",
                category=category,
                file_path=left.file_path,
                rule_name=left.name,
                evidence=(
                    f"other_file={right.file_path}",
                    f"other_alert={right.name}",
                    f"reason={reason}",
                ),
            )
        )
    return findings


def _near_duplicate_pairs(
    alerts: list[RuleRecord],
) -> list[tuple[RuleRecord, RuleRecord, str]]:
    """Conservative near-duplicates: same normalized expr + same severity label.

    Requires different alert names (exact expression duplicates are reported
    separately) so this only surfaces renamed clones.
    """
    pairs: list[tuple[RuleRecord, RuleRecord, str]] = []
    for index, left in enumerate(alerts):
        left_expr = normalize_expr(left.expr)
        if not left_expr or not left.name:
            continue
        left_sev = dict(left.labels).get("severity", "")
        for right in alerts[index + 1 :]:
            if not right.name or left.name == right.name:
                continue
            right_expr = normalize_expr(right.expr)
            if left_expr != right_expr:
                continue
            right_sev = dict(right.labels).get("severity", "")
            if left_sev != right_sev:
                continue
            pairs.append(
                (
                    left,
                    right,
                    "identical normalized expr and severity label, different names",
                )
            )
    return pairs
