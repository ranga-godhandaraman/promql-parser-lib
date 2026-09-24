"""``dude_rushup.wild()`` — repository noise-risk analysis entry point."""

from __future__ import annotations

from pathlib import Path

from promql_analyzer.dude_rushup._base import rebuild_report
from promql_analyzer.dude_rushup.context import AnalysisContext
from promql_analyzer.dude_rushup.inventory import build_inventory
from promql_analyzer.dude_rushup.noise import NoiseRiskAnalyzer
from promql_analyzer.dude_rushup.noise_models import NoiseRiskConfig
from promql_analyzer.repository.models import RepositoryReport, RepositoryScanConfig


def wild(
    path: Path | str,
    config: NoiseRiskConfig | None = None,
    *,
    scan_config: RepositoryScanConfig | None = None,
    context: AnalysisContext | None = None,
) -> RepositoryReport:
    """Analyze alert noise *risk* for a file, folder, or repository.

    When ``context`` is provided (e.g. from ``comeup_360``), the repository is
    not scanned again.
    """
    cfg = config if config is not None else NoiseRiskConfig()
    effective_scan = scan_config if scan_config is not None else cfg.scan
    ctx = context or AnalysisContext.from_path(path, scan_config=effective_scan)

    analyzer = NoiseRiskAnalyzer(cfg)
    assessments = analyzer.assess_many(ctx.report.alerts)
    findings = tuple(analyzer.to_finding(item) for item in assessments)
    noise_summary = analyzer.summarize(assessments)
    inventory = build_inventory(ctx.report.alerts, ctx.report.recording_rules)

    return rebuild_report(
        ctx.report,
        findings,
        inventory=inventory,
        noise_assessments=tuple(assessments),
        noise_summary=noise_summary,
    )
