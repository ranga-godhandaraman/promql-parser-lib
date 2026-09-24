"""V2 repository-level analysis models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from promql_analyzer.models import AnalysisResult, Finding, Severity

if TYPE_CHECKING:
    from promql_analyzer.dude_rushup.inventory import RepositoryInventory
    from promql_analyzer.dude_rushup.noise_models import (
        NoiseRiskAssessment,
        NoiseRiskSummary,
    )
    from promql_analyzer.dude_rushup.speakup_models import SpeakupSuggestion


@dataclass(frozen=True)
class RuleRecord:
    """An alert, recording rule, or condition document from a repository scan."""

    file_path: str
    kind: str  # "alert" | "record" | "condition" | "unknown"
    name: str | None
    expr: str | None
    group_name: str | None = None
    location: str = ""
    labels: tuple[tuple[str, str], ...] = ()
    annotations: tuple[tuple[str, str], ...] = ()
    for_duration: str | None = None
    parse_error: str | None = None
    analysis: AnalysisResult | None = None
    # Extraction hints used by ``dude_rushup.broken()``.
    # ``expr_*`` flags refer to the PromQL field (``expr``, ``condition``, …).
    expr_present: bool = False
    expr_empty: bool = False
    expr_non_string: bool = False
    labels_malformed: bool = False
    annotations_malformed: bool = False
    name_empty: bool = False
    for_malformed: bool = False

    @property
    def is_alert_like(self) -> bool:
        """True for Prometheus alerts and condition-style alert documents."""
        return self.kind in ("alert", "condition")


# Alert-focused alias for readability in repository APIs.
AlertRecord = RuleRecord


@dataclass(frozen=True)
class FailedFile:
    """A file that could not be parsed or processed."""

    path: str
    error: str


@dataclass(frozen=True)
class AnalysisSummary:
    """Aggregate statistics for a repository scan."""

    files_scanned: int = 0
    files_parsed: int = 0
    files_failed: int = 0
    files_skipped: int = 0
    alerts: int = 0
    recording_rules: int = 0
    findings: int = 0
    findings_by_severity: tuple[tuple[str, int], ...] = ()


@dataclass(frozen=True)
class RepositoryReport:
    """Unified report for a repository/folder scan."""

    root: str
    scanned_files: tuple[str, ...] = ()
    parsed_files: tuple[str, ...] = ()
    skipped_files: tuple[str, ...] = ()
    failed_files: tuple[FailedFile, ...] = ()
    alerts: tuple[RuleRecord, ...] = ()
    recording_rules: tuple[RuleRecord, ...] = ()
    findings: tuple[Finding, ...] = ()
    summary: AnalysisSummary = field(default_factory=AnalysisSummary)
    # Populated by ``dude_rushup.wild()`` / ``speakup()`` / comeup_360.
    noise_assessments: tuple[NoiseRiskAssessment, ...] = ()
    noise_summary: NoiseRiskSummary | None = None
    inventory: RepositoryInventory | None = None
    speakup_suggestions: tuple[SpeakupSuggestion, ...] = ()

    @property
    def rules(self) -> tuple[RuleRecord, ...]:
        """All discovered alert and recording rules."""
        return (*self.alerts, *self.recording_rules)

    def to_json(self, path: str | None = None, *, indent: int = 2) -> str:
        """Export this report as JSON (see ``promql_analyzer.exporters``)."""
        from promql_analyzer.exporters import to_json

        return to_json(self, path, indent=indent)

    def to_csv(self, path: str | None = None) -> str:
        """Export findings as CSV."""
        from promql_analyzer.exporters import to_csv

        return to_csv(self, path)

    def to_tsv(self, path: str | None = None) -> str:
        """Export findings as TSV."""
        from promql_analyzer.exporters import to_tsv

        return to_tsv(self, path)

    def to_excel(self, path: str) -> None:
        """Export a multi-sheet Excel workbook (requires openpyxl extra)."""
        from promql_analyzer.exporters import to_excel

        to_excel(self, path)


@dataclass(frozen=True)
class RepositoryScanConfig:
    """Configuration for repository discovery and foundation scanning."""

    include_globs: tuple[str, ...] = ("**/*.yaml", "**/*.yml")
    exclude_globs: tuple[str, ...] = (
        "**/.git/**",
        "**/node_modules/**",
        "**/vendor/**",
        "**/.venv/**",
        "**/venv/**",
        "**/__pycache__/**",
    )
    follow_symlinks: bool = False
    # When True, run existing PromQL analysis (dude_look / PQL rules) on exprs.
    analyze_promql: bool = True
    # Attach file_path / rule_name onto findings copied from query analysis.
    enrich_findings: bool = True


def build_summary(
    *,
    scanned_files: tuple[str, ...],
    parsed_files: tuple[str, ...],
    skipped_files: tuple[str, ...],
    failed_files: tuple[FailedFile, ...],
    alerts: tuple[RuleRecord, ...],
    recording_rules: tuple[RuleRecord, ...],
    findings: tuple[Finding, ...],
) -> AnalysisSummary:
    """Build an ``AnalysisSummary`` from report components."""
    severity_counts: dict[str, int] = {}
    for finding in findings:
        key = (
            finding.severity.value
            if isinstance(finding.severity, Severity)
            else str(finding.severity)
        )
        severity_counts[key] = severity_counts.get(key, 0) + 1

    return AnalysisSummary(
        files_scanned=len(scanned_files),
        files_parsed=len(parsed_files),
        files_failed=len(failed_files),
        files_skipped=len(skipped_files),
        alerts=len(alerts),
        recording_rules=len(recording_rules),
        findings=len(findings),
        findings_by_severity=tuple(sorted(severity_counts.items())),
    )
