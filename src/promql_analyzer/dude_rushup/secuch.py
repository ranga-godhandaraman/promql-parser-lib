"""``dude_rushup.secuch()`` — configurable security policy / hygiene checks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from promql_analyzer.dude_rushup._base import make_finding, rebuild_report
from promql_analyzer.dude_rushup.context import AnalysisContext
from promql_analyzer.dude_rushup.inventory import (
    build_inventory,
    repository_findings,
)
from promql_analyzer.models import Finding, Severity
from promql_analyzer.repository.models import (
    RepositoryReport,
    RepositoryScanConfig,
    RuleRecord,
)

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


@dataclass(frozen=True)
class SecuchConfig:
    """Organizational security/policy hygiene configuration.

    Distinct from ``vuln()``: these are policy requirements, not secret exposure
    heuristics. Empty defaults mean checks are opt-in.
    """

    required_labels: tuple[str, ...] = ()
    required_annotations: tuple[str, ...] = ()
    # Alert must include at least one of these ownership labels when non-empty.
    ownership_labels_any_of: tuple[str, ...] = ()
    # Alert must include at least one of these runbook annotations when non-empty.
    runbook_annotations_any_of: tuple[str, ...] = ()
    forbidden_labels: tuple[str, ...] = ()
    # Exact (label, value) pairs that are forbidden.
    forbidden_label_values: tuple[tuple[str, str], ...] = ()
    # Regex patterns that annotation values must not match.
    blocked_annotation_patterns: tuple[str, ...] = ()
    # Regex patterns that annotation values must match when the key is listed.
    required_annotation_patterns: tuple[tuple[str, str], ...] = ()
    # When non-empty, http(s) URLs in annotations must be on these domains.
    allowed_url_domains: tuple[str, ...] = ()
    check_duplicate_names: bool = True
    check_duplicate_exprs: bool = False
    check_near_duplicates: bool = False
    scan: RepositoryScanConfig = field(
        default_factory=lambda: RepositoryScanConfig(
            analyze_promql=False,
            enrich_findings=False,
        )
    )


def secuch(
    path: Path | str,
    config: SecuchConfig | None = None,
    *,
    scan_config: RepositoryScanConfig | None = None,
    context: AnalysisContext | None = None,
) -> RepositoryReport:
    """Run configurable security policy / hygiene checks on alert rules."""
    cfg = config if config is not None else SecuchConfig()
    effective_scan = scan_config if scan_config is not None else cfg.scan
    ctx = context or AnalysisContext.from_path(path, scan_config=effective_scan)
    analyzer = SecuchAnalyzer(cfg)
    findings = analyzer.analyze_report(ctx.report)
    inventory = build_inventory(
        ctx.report.alerts,
        ctx.report.recording_rules,
        ownership_keys=cfg.ownership_labels_any_of or ("owner", "team"),
        runbook_keys=cfg.runbook_annotations_any_of or ("runbook_url", "runbook"),
    )
    return rebuild_report(ctx.report, findings, inventory=inventory)


class SecuchAnalyzer:
    """Policy/hygiene checks driven by ``SecuchConfig``."""

    def __init__(self, config: SecuchConfig | None = None) -> None:
        self.config = config if config is not None else SecuchConfig()
        self._blocked_ann = tuple(
            re.compile(p) for p in self.config.blocked_annotation_patterns
        )
        self._required_ann_patterns = tuple(
            (key, re.compile(pattern))
            for key, pattern in self.config.required_annotation_patterns
        )

    def analyze_report(self, report: RepositoryReport) -> list[Finding]:
        findings: list[Finding] = []
        for rule in report.alerts:
            findings.extend(self.analyze_alert(rule))
        findings.extend(
            repository_findings(
                report.alerts,
                check_duplicate_names=self.config.check_duplicate_names,
                check_duplicate_exprs=self.config.check_duplicate_exprs,
                check_near_duplicates=self.config.check_near_duplicates,
                category="secuch",
                rule_id_prefix="SECUCHDUP",
            )
        )
        return findings

    def analyze_alert(self, rule: RuleRecord) -> list[Finding]:
        findings: list[Finding] = []
        labels = dict(rule.labels)
        annotations = dict(rule.annotations)
        label_keys = set(labels)
        ann_keys = set(annotations)

        for key in self.config.required_labels:
            if key not in label_keys:
                findings.append(
                    make_finding(
                        rule_id="SECUCH001",
                        severity=Severity.WARNING,
                        message=f"Missing required policy label {key!r}",
                        explanation="Organizational policy requires this label on alerts.",
                        suggestion=f"Add labels.{key}.",
                        category="secuch",
                        file_path=rule.file_path,
                        rule_name=rule.name,
                        evidence=(f"required_label={key}",),
                    )
                )

        for key in self.config.required_annotations:
            if key not in ann_keys:
                findings.append(
                    make_finding(
                        rule_id="SECUCH002",
                        severity=Severity.WARNING,
                        message=f"Missing required policy annotation {key!r}",
                        explanation=(
                            "Organizational policy requires this annotation on alerts."
                        ),
                        suggestion=f"Add annotations.{key}.",
                        category="secuch",
                        file_path=rule.file_path,
                        rule_name=rule.name,
                        evidence=(f"required_annotation={key}",),
                    )
                )

        if self.config.ownership_labels_any_of:
            if not any(k in label_keys for k in self.config.ownership_labels_any_of):
                findings.append(
                    make_finding(
                        rule_id="SECUCH003",
                        severity=Severity.WARNING,
                        message="Missing ownership metadata",
                        explanation=(
                            "Alert has none of the configured ownership labels: "
                            + ", ".join(self.config.ownership_labels_any_of)
                        ),
                        suggestion="Add an ownership label such as owner or team.",
                        category="secuch",
                        file_path=rule.file_path,
                        rule_name=rule.name,
                        evidence=(
                            "ownership_labels="
                            + ",".join(self.config.ownership_labels_any_of),
                        ),
                    )
                )

        if self.config.runbook_annotations_any_of:
            if not any(k in ann_keys for k in self.config.runbook_annotations_any_of):
                findings.append(
                    make_finding(
                        rule_id="SECUCH004",
                        severity=Severity.WARNING,
                        message="Missing runbook metadata",
                        explanation=(
                            "Alert has none of the configured runbook annotations: "
                            + ", ".join(self.config.runbook_annotations_any_of)
                        ),
                        suggestion="Add a runbook_url (or equivalent) annotation.",
                        category="secuch",
                        file_path=rule.file_path,
                        rule_name=rule.name,
                        evidence=(
                            "runbook_annotations="
                            + ",".join(self.config.runbook_annotations_any_of),
                        ),
                    )
                )

        for key in self.config.forbidden_labels:
            if key in label_keys:
                findings.append(
                    make_finding(
                        rule_id="SECUCH005",
                        severity=Severity.ERROR,
                        message=f"Forbidden label {key!r} present",
                        explanation="Organizational policy forbids this label on alerts.",
                        suggestion=f"Remove labels.{key}.",
                        category="secuch",
                        file_path=rule.file_path,
                        rule_name=rule.name,
                        evidence=(f"forbidden_label={key}",),
                    )
                )

        for key, value in self.config.forbidden_label_values:
            if labels.get(key) == value:
                findings.append(
                    make_finding(
                        rule_id="SECUCH006",
                        severity=Severity.ERROR,
                        message=f"Forbidden label value {key}={value!r}",
                        explanation=(
                            "Organizational policy forbids this label/value combination."
                        ),
                        suggestion=f"Change or remove labels.{key}.",
                        category="secuch",
                        file_path=rule.file_path,
                        rule_name=rule.name,
                        evidence=(f"label={key}", f"value={value}"),
                    )
                )

        for key, value in annotations.items():
            for pattern in self._blocked_ann:
                if pattern.search(value):
                    findings.append(
                        make_finding(
                            rule_id="SECUCH007",
                            severity=Severity.WARNING,
                            message=f"Annotation {key!r} matches blocked pattern",
                            explanation=(
                                "Annotation value matches a configured blocked pattern."
                            ),
                            suggestion="Update the annotation to comply with policy.",
                            category="secuch",
                            file_path=rule.file_path,
                            rule_name=rule.name,
                            evidence=(f"annotation={key}", f"pattern={pattern.pattern}"),
                        )
                    )

        for key, pattern in self._required_ann_patterns:
            value = annotations.get(key)
            if value is None:
                continue
            if not pattern.search(value):
                findings.append(
                    make_finding(
                        rule_id="SECUCH008",
                        severity=Severity.WARNING,
                        message=f"Annotation {key!r} does not match required pattern",
                        explanation=(
                            "Annotation is present but does not satisfy the configured "
                            "allowed pattern."
                        ),
                        suggestion=f"Update annotations.{key} to match policy.",
                        category="secuch",
                        file_path=rule.file_path,
                        rule_name=rule.name,
                        evidence=(f"annotation={key}", f"pattern={pattern.pattern}"),
                    )
                )

        if self.config.allowed_url_domains:
            allowed = {d.lower().lstrip(".") for d in self.config.allowed_url_domains}
            for key, value in annotations.items():
                for url in _URL_RE.findall(value):
                    host = (urlparse(url).hostname or "").lower()
                    if not host:
                        continue
                    if not any(host == d or host.endswith("." + d) for d in allowed):
                        findings.append(
                            make_finding(
                                rule_id="SECUCH009",
                                severity=Severity.WARNING,
                                message=f"URL domain not in allowlist ({host})",
                                explanation=(
                                    f"Annotation {key!r} references {url} whose domain "
                                    "is outside the configured allowlist."
                                ),
                                suggestion="Use an approved documentation/runbook domain.",
                                category="secuch",
                                file_path=rule.file_path,
                                rule_name=rule.name,
                                evidence=(
                                    f"annotation={key}",
                                    f"host={host}",
                                    "allowed=" + ",".join(sorted(allowed)),
                                ),
                            )
                        )

        return findings
