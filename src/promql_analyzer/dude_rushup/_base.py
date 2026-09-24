"""Shared helpers for ``dude_rushup`` analyzers."""

from __future__ import annotations

from pathlib import Path

from promql_analyzer.models import Finding, Severity
from promql_analyzer.repository.models import (
    RepositoryReport,
    RepositoryScanConfig,
    build_summary,
)
from promql_analyzer.repository.pipeline import RepositoryAnalyzer


def scan_rules(
    path: Path | str,
    *,
    scan_config: RepositoryScanConfig | None = None,
) -> RepositoryReport:
    """Discover and extract rules without running PQL lint analysis."""
    effective = scan_config if scan_config is not None else RepositoryScanConfig()
    scan = RepositoryScanConfig(
        include_globs=effective.include_globs,
        exclude_globs=effective.exclude_globs,
        follow_symlinks=effective.follow_symlinks,
        analyze_promql=False,
        enrich_findings=False,
    )
    return RepositoryAnalyzer(scan_config=scan).analyze(path)


def rebuild_report(
    base: RepositoryReport,
    findings: tuple[Finding, ...] | list[Finding],
    **extra: object,
) -> RepositoryReport:
    """Return a ``RepositoryReport`` with new findings and optional extras."""
    findings_t = tuple(findings)
    summary = build_summary(
        scanned_files=base.scanned_files,
        parsed_files=base.parsed_files,
        skipped_files=base.skipped_files,
        failed_files=base.failed_files,
        alerts=base.alerts,
        recording_rules=base.recording_rules,
        findings=findings_t,
    )
    payload = {
        "root": base.root,
        "scanned_files": base.scanned_files,
        "parsed_files": base.parsed_files,
        "skipped_files": base.skipped_files,
        "failed_files": base.failed_files,
        "alerts": base.alerts,
        "recording_rules": base.recording_rules,
        "findings": findings_t,
        "summary": summary,
        "noise_assessments": base.noise_assessments,
        "noise_summary": base.noise_summary,
        "inventory": getattr(base, "inventory", None),
        "speakup_suggestions": getattr(base, "speakup_suggestions", ()),
    }
    payload.update(extra)
    return RepositoryReport(**payload)  # type: ignore[arg-type]


def make_finding(
    *,
    rule_id: str,
    severity: Severity,
    message: str,
    explanation: str,
    category: str,
    file_path: str | None = None,
    rule_name: str | None = None,
    suggestion: str | None = None,
    score: float | None = None,
    evidence: tuple[str, ...] = (),
) -> Finding:
    """Build a ``Finding`` with repository context fields."""
    return Finding(
        rule_id=rule_id,
        severity=severity,
        message=message,
        explanation=explanation,
        suggestion=suggestion,
        category=category,
        score=score,
        evidence=evidence,
        file_path=file_path,
        rule_name=rule_name,
    )


def risk_to_severity(level: str) -> Severity:
    """Map LOW/MEDIUM/HIGH/CRITICAL wording onto Finding severities."""
    normalized = level.strip().upper()
    if normalized in {"CRITICAL", "HIGH"}:
        return Severity.ERROR
    if normalized == "MEDIUM":
        return Severity.WARNING
    return Severity.INFO
