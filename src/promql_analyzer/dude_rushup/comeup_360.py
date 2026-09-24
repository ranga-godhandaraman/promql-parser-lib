"""``dude_rushup.comeup_360()`` — run all analyzers on one shared scan."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from promql_analyzer.dude_rushup._base import rebuild_report
from promql_analyzer.dude_rushup.broken import BrokenAnalyzer
from promql_analyzer.dude_rushup.config import RushupConfig
from promql_analyzer.dude_rushup.context import AnalysisContext
from promql_analyzer.dude_rushup.inventory import build_inventory
from promql_analyzer.dude_rushup.noise import NoiseRiskAnalyzer
from promql_analyzer.dude_rushup.secuch import SecuchAnalyzer
from promql_analyzer.dude_rushup.speakup import SpeakupAnalyzer
from promql_analyzer.dude_rushup.vuln import VulnAnalyzer
from promql_analyzer.models import Finding
from promql_analyzer.repository.models import RepositoryReport, RepositoryScanConfig


def comeup_360(
    path: Path | str,
    config: RushupConfig | None = None,
    *,
    scan_config: RepositoryScanConfig | None = None,
    context: AnalysisContext | None = None,
) -> RepositoryReport:
    """Run wild/broken/vuln/secuch/speakup on a shared repository context.

    Pipeline (single pass)::

        discover → parse YAML → extract rules → shared context
            → analyzers → aggregate findings → RepositoryReport

    Analyzers never re-scan independently when called through this entry point.
    """
    cfg = config if config is not None else RushupConfig()
    effective_scan = scan_config if scan_config is not None else cfg.to_scan_config()
    ctx = context or AnalysisContext.from_path(path, scan_config=effective_scan)
    return run_analyzers(ctx, cfg)


def run_analyzers(ctx: AnalysisContext, config: RushupConfig) -> RepositoryReport:
    """Execute enabled analyzers against an existing ``AnalysisContext``."""
    findings: list[Finding] = []
    noise_assessments = ()
    noise_summary = None
    speakup_suggestions = ()

    base = ctx.report

    if config.enable_broken:
        findings.extend(BrokenAnalyzer(config.resolved_broken()).analyze_report(base))

    if config.enable_wild:
        wild_analyzer = NoiseRiskAnalyzer(config.resolved_wild())
        assessments = wild_analyzer.assess_many(base.alerts)
        noise_assessments = tuple(assessments)
        noise_summary = wild_analyzer.summarize(assessments)
        findings.extend(wild_analyzer.to_finding(item) for item in assessments)

    if config.enable_vuln:
        findings.extend(VulnAnalyzer(config.resolved_vuln()).analyze_report(base))

    if config.enable_secuch:
        secuch_cfg = config.resolved_secuch()
        # Avoid duplicate repository-identity findings when broken() already ran.
        if config.enable_broken:
            secuch_cfg = replace(
                secuch_cfg,
                check_duplicate_names=False,
                check_duplicate_exprs=False,
                check_near_duplicates=False,
            )
        findings.extend(SecuchAnalyzer(secuch_cfg).analyze_report(base))

    if config.enable_speakup:
        speakup_analyzer = SpeakupAnalyzer(config.resolved_speakup())
        suggestions = speakup_analyzer.analyze_report(base)
        speakup_suggestions = tuple(suggestions)
        findings.extend(item.finding for item in suggestions)

    inventory = build_inventory(base.alerts, base.recording_rules)
    return rebuild_report(
        base,
        findings,
        inventory=inventory,
        noise_assessments=noise_assessments,
        noise_summary=noise_summary,
        speakup_suggestions=speakup_suggestions,
    )
