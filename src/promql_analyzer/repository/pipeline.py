"""Repository analysis pipeline foundation.

Flow:
    discovery -> YAML parsing -> rule extraction -> PromQL analysis -> report

Specialized V2 analyzers (wild/broken/vuln/secuch/speakup) will plug into this
pipeline later. This module only builds the shared foundation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from promql_analyzer.analyze import dude_look
from promql_analyzer.models import AnalyzerConfig, Finding
from promql_analyzer.parser import PromQLSyntaxError
from promql_analyzer.repository.extract import extract_rule_records
from promql_analyzer.repository.models import (
    FailedFile,
    RepositoryReport,
    RepositoryScanConfig,
    RuleRecord,
    build_summary,
)
from promql_analyzer.repository.scanner import DiscoveredFile, RepositoryScanner


class RepositoryAnalyzer:
    """Scan a repository/folder and build a ``RepositoryReport``."""

    def __init__(
        self,
        scan_config: RepositoryScanConfig | None = None,
        analyzer_config: AnalyzerConfig | None = None,
    ) -> None:
        self.scan_config = scan_config if scan_config is not None else RepositoryScanConfig()
        self.analyzer_config = analyzer_config
        self.scanner = RepositoryScanner(self.scan_config)

    def analyze(self, root: Path | str) -> RepositoryReport:
        """Run the foundation repository analysis pipeline."""
        root_path = Path(root).resolve()
        discovered = self.scanner.discover(root_path)

        scanned_files: list[str] = []
        parsed_files: list[str] = []
        skipped_files: list[str] = []
        failed_files: list[FailedFile] = []
        alerts: list[RuleRecord] = []
        recording_rules: list[RuleRecord] = []
        findings: list[Finding] = []

        for item in discovered:
            display_path = _display_path(root_path, item)
            scanned_files.append(display_path)
            try:
                documents = _load_yaml_documents(item.path)
            except Exception as exc:  # noqa: BLE001 - isolate per-file failures
                failed_files.append(FailedFile(path=display_path, error=str(exc)))
                continue

            file_rules: list[RuleRecord] = []
            for document in documents:
                file_rules.extend(
                    extract_rule_records(document, file_path=display_path)
                )

            if not file_rules:
                # Valid YAML, but not Prometheus rules — skip gracefully.
                skipped_files.append(display_path)
                continue

            parsed_files.append(display_path)
            enriched_rules = [
                self._enrich_rule(rule) if self.scan_config.analyze_promql else rule
                for rule in file_rules
            ]
            for rule in enriched_rules:
                if rule.kind in ("alert", "condition"):
                    alerts.append(rule)
                elif rule.kind == "record":
                    recording_rules.append(rule)
                else:
                    # Unknown kind with expr still tracked as recording-like inventory.
                    recording_rules.append(rule)

                if rule.analysis is not None and self.scan_config.enrich_findings:
                    findings.extend(
                        _enrich_finding(finding, rule) for finding in rule.analysis.findings
                    )

        summary = build_summary(
            scanned_files=tuple(scanned_files),
            parsed_files=tuple(parsed_files),
            skipped_files=tuple(skipped_files),
            failed_files=tuple(failed_files),
            alerts=tuple(alerts),
            recording_rules=tuple(recording_rules),
            findings=tuple(findings),
        )
        return RepositoryReport(
            root=str(root_path),
            scanned_files=tuple(scanned_files),
            parsed_files=tuple(parsed_files),
            skipped_files=tuple(skipped_files),
            failed_files=tuple(failed_files),
            alerts=tuple(alerts),
            recording_rules=tuple(recording_rules),
            findings=tuple(findings),
            summary=summary,
        )

    def _enrich_rule(self, rule: RuleRecord) -> RuleRecord:
        if not rule.expr:
            return rule
        try:
            analysis = dude_look(rule.expr, config=self.analyzer_config)
            return RuleRecord(
                file_path=rule.file_path,
                kind=rule.kind,
                name=rule.name,
                expr=rule.expr,
                group_name=rule.group_name,
                location=rule.location,
                labels=rule.labels,
                annotations=rule.annotations,
                for_duration=rule.for_duration,
                parse_error=None,
                analysis=analysis,
                expr_present=rule.expr_present,
                expr_empty=rule.expr_empty,
                expr_non_string=rule.expr_non_string,
                labels_malformed=rule.labels_malformed,
                annotations_malformed=rule.annotations_malformed,
                name_empty=rule.name_empty,
                for_malformed=rule.for_malformed,
            )
        except PromQLSyntaxError as exc:
            return RuleRecord(
                file_path=rule.file_path,
                kind=rule.kind,
                name=rule.name,
                expr=rule.expr,
                group_name=rule.group_name,
                location=rule.location,
                labels=rule.labels,
                annotations=rule.annotations,
                for_duration=rule.for_duration,
                parse_error=str(exc),
                analysis=None,
                expr_present=rule.expr_present,
                expr_empty=rule.expr_empty,
                expr_non_string=rule.expr_non_string,
                labels_malformed=rule.labels_malformed,
                annotations_malformed=rule.annotations_malformed,
                name_empty=rule.name_empty,
                for_malformed=rule.for_malformed,
            )


def _load_yaml_documents(path: Path) -> list[Any]:
    text = path.read_text(encoding="utf-8")
    if not text.strip():
        raise ValueError("file is empty")
    documents = list(yaml.safe_load_all(text))
    # Filter out empty documents from trailing separators.
    return [doc for doc in documents if doc is not None]


def _display_path(root: Path, item: DiscoveredFile) -> str:
    if root.is_file():
        return root.name
    return item.relative_path


def _enrich_finding(finding: Finding, rule: RuleRecord) -> Finding:
    return Finding(
        rule_id=finding.rule_id,
        severity=finding.severity,
        message=finding.message,
        explanation=finding.explanation,
        suggestion=finding.suggestion,
        category=finding.category or "lint",
        score=finding.score,
        evidence=finding.evidence,
        file_path=rule.file_path,
        rule_name=rule.name,
    )
