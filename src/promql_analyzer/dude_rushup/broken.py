"""``dude_rushup.broken()`` — incomplete / invalid rule detection."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from promql_analyzer.dude_rushup._base import make_finding, rebuild_report
from promql_analyzer.dude_rushup.context import AnalysisContext
from promql_analyzer.dude_rushup.inventory import (
    build_inventory,
    repository_findings,
)
from promql_analyzer.models import Finding, Severity
from promql_analyzer.parser import PromQLSyntaxError, parse_query
from promql_analyzer.repository.models import (
    FailedFile,
    RepositoryReport,
    RepositoryScanConfig,
    RuleRecord,
)


@dataclass(frozen=True)
class BrokenConfig:
    """Configuration for broken/incomplete rule analysis.

    Required metadata is opt-in so optional Prometheus fields are not
    blindly treated as broken.
    """

    required_alert_labels: tuple[str, ...] = ()
    required_alert_annotations: tuple[str, ...] = ()
    required_record_labels: tuple[str, ...] = ()
    require_for_on_alerts: bool = False
    validate_promql: bool = True
    check_duplicate_names: bool = True
    check_duplicate_exprs: bool = True
    check_near_duplicates: bool = True
    scan: RepositoryScanConfig = field(
        default_factory=lambda: RepositoryScanConfig(
            analyze_promql=False,
            enrich_findings=False,
        )
    )


def broken(
    path: Path | str,
    config: BrokenConfig | None = None,
    *,
    scan_config: RepositoryScanConfig | None = None,
    context: AnalysisContext | None = None,
) -> RepositoryReport:
    """Detect broken or incomplete Prometheus alert/rule definitions."""
    cfg = config if config is not None else BrokenConfig()
    effective_scan = scan_config if scan_config is not None else cfg.scan
    ctx = context or AnalysisContext.from_path(path, scan_config=effective_scan)

    analyzer = BrokenAnalyzer(cfg)
    findings = analyzer.analyze_report(ctx.report)
    inventory = build_inventory(ctx.report.alerts, ctx.report.recording_rules)
    return rebuild_report(ctx.report, findings, inventory=inventory)


class BrokenAnalyzer:
    """Produce structured findings for invalid/incomplete rules."""

    def __init__(self, config: BrokenConfig | None = None) -> None:
        self.config = config if config is not None else BrokenConfig()

    def analyze_report(self, report: RepositoryReport) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._failed_file_findings(report.failed_files))
        for rule in report.rules:
            findings.extend(self.analyze_rule(rule))
        findings.extend(
            repository_findings(
                report.alerts,
                check_duplicate_names=self.config.check_duplicate_names,
                check_duplicate_exprs=self.config.check_duplicate_exprs,
                check_near_duplicates=self.config.check_near_duplicates,
                category="broken",
                rule_id_prefix="BROKENDUP",
            )
        )
        return findings

    def analyze_rule(self, rule: RuleRecord) -> list[Finding]:
        findings: list[Finding] = []
        name = rule.name

        if rule.name_empty or not rule.name:
            findings.append(
                make_finding(
                    rule_id="BROKEN010",
                    severity=Severity.ERROR,
                    message=f"Missing or empty {rule.kind} name",
                    explanation=(
                        f"Rule object declares {rule.kind!r} but the name is "
                        "missing or empty."
                    ),
                    suggestion=f"Set a non-empty `{rule.kind}:` name.",
                    category="broken",
                    file_path=rule.file_path,
                    rule_name=name,
                    evidence=(f"kind={rule.kind}", f"location={rule.location}"),
                )
            )

        if not rule.expr_present:
            findings.append(
                make_finding(
                    rule_id="BROKEN011",
                    severity=Severity.ERROR,
                    message="Missing PromQL expression field",
                    explanation=(
                        "Rules need a PromQL expression under a common field "
                        "such as `expr`, `condition`, `query`, or `promql`."
                    ),
                    suggestion="Add a PromQL expression for this rule.",
                    category="broken",
                    file_path=rule.file_path,
                    rule_name=name,
                    evidence=(f"kind={rule.kind}",),
                )
            )
        elif rule.expr_empty:
            findings.append(
                make_finding(
                    rule_id="BROKEN012",
                    severity=Severity.ERROR,
                    message="Empty PromQL expression field",
                    explanation="A PromQL field is present but empty.",
                    suggestion="Provide a valid PromQL expression.",
                    category="broken",
                    file_path=rule.file_path,
                    rule_name=name,
                )
            )
        elif rule.expr_non_string:
            findings.append(
                make_finding(
                    rule_id="BROKEN013",
                    severity=Severity.ERROR,
                    message="Malformed PromQL expression field (not a string)",
                    explanation=(
                        "The PromQL field (`expr`, `condition`, …) must be a "
                        "YAML string containing PromQL."
                    ),
                    suggestion="Quote the PromQL expression as a string.",
                    category="broken",
                    file_path=rule.file_path,
                    rule_name=name,
                )
            )
        elif rule.expr and self.config.validate_promql:
            try:
                parse_query(rule.expr)
            except PromQLSyntaxError as exc:
                findings.append(
                    make_finding(
                        rule_id="BROKEN014",
                        severity=Severity.ERROR,
                        message="Invalid PromQL expression",
                        explanation=exc.message,
                        suggestion="Fix the PromQL syntax in the expression field.",
                        category="broken",
                        file_path=rule.file_path,
                        rule_name=name,
                        evidence=(f"expr={rule.expr}",),
                    )
                )

        if rule.labels_malformed:
            findings.append(
                make_finding(
                    rule_id="BROKEN015",
                    severity=Severity.ERROR,
                    message="Malformed labels field",
                    explanation="`labels` must be a mapping of string keys to scalar values.",
                    suggestion="Use a YAML mapping for labels.",
                    category="broken",
                    file_path=rule.file_path,
                    rule_name=name,
                )
            )
        else:
            for key, value in rule.labels:
                if value.startswith("<") and value.endswith(">"):
                    findings.append(
                        make_finding(
                            rule_id="BROKEN016",
                            severity=Severity.WARNING,
                            message=f"Non-scalar label value for {key!r}",
                            explanation=(
                                "Label values should be scalars; nested structures "
                                "are invalid in Prometheus rules."
                            ),
                            suggestion="Use a string/number/boolean label value.",
                            category="broken",
                            file_path=rule.file_path,
                            rule_name=name,
                            evidence=(f"label={key}", f"value={value}"),
                        )
                    )

        if rule.annotations_malformed:
            findings.append(
                make_finding(
                    rule_id="BROKEN017",
                    severity=Severity.ERROR,
                    message="Malformed annotations field",
                    explanation=(
                        "`annotations` must be a mapping of string keys to scalar values."
                    ),
                    suggestion="Use a YAML mapping for annotations.",
                    category="broken",
                    file_path=rule.file_path,
                    rule_name=name,
                )
            )
        else:
            for key, value in rule.annotations:
                if value.startswith("<") and value.endswith(">"):
                    findings.append(
                        make_finding(
                            rule_id="BROKEN018",
                            severity=Severity.WARNING,
                            message=f"Non-scalar annotation value for {key!r}",
                            explanation=(
                                "Annotation values should be scalars in Prometheus rules."
                            ),
                            suggestion="Use a string annotation value.",
                            category="broken",
                            file_path=rule.file_path,
                            rule_name=name,
                            evidence=(f"annotation={key}", f"value={value}"),
                        )
                    )

        if rule.for_malformed:
            findings.append(
                make_finding(
                    rule_id="BROKEN019",
                    severity=Severity.WARNING,
                    message="Malformed for duration",
                    explanation="`for` must be a Prometheus duration string such as `5m`.",
                    suggestion="Set `for` to a duration string, or omit it.",
                    category="broken",
                    file_path=rule.file_path,
                    rule_name=name,
                )
            )

        if rule.kind == "alert" and self.config.require_for_on_alerts and not rule.for_duration:
            findings.append(
                make_finding(
                    rule_id="BROKEN020",
                    severity=Severity.WARNING,
                    message="Missing for duration on alert",
                    explanation=(
                        "Configuration requires alerts to declare a `for` debounce window."
                    ),
                    suggestion="Add a `for:` duration to this alert.",
                    category="broken",
                    file_path=rule.file_path,
                    rule_name=name,
                )
            )

        required_labels = (
            self.config.required_alert_labels
            if rule.kind == "alert"
            else self.config.required_record_labels
        )
        if required_labels:
            present = {k for k, _ in rule.labels}
            for key in required_labels:
                if key not in present:
                    findings.append(
                        make_finding(
                            rule_id="BROKEN021",
                            severity=Severity.WARNING,
                            message=f"Missing required label {key!r}",
                            explanation=(
                                "Configured required label is absent on this rule."
                            ),
                            suggestion=f"Add labels.{key}.",
                            category="broken",
                            file_path=rule.file_path,
                            rule_name=name,
                            evidence=(f"required_label={key}",),
                        )
                    )

        if rule.kind == "alert" and self.config.required_alert_annotations:
            present_ann = {k for k, _ in rule.annotations}
            for key in self.config.required_alert_annotations:
                if key not in present_ann:
                    findings.append(
                        make_finding(
                            rule_id="BROKEN022",
                            severity=Severity.WARNING,
                            message=f"Missing required annotation {key!r}",
                            explanation=(
                                "Configured required annotation is absent on this alert."
                            ),
                            suggestion=f"Add annotations.{key}.",
                            category="broken",
                            file_path=rule.file_path,
                            rule_name=name,
                            evidence=(f"required_annotation={key}",),
                        )
                    )

        return findings

    def _failed_file_findings(self, failed: tuple[FailedFile, ...]) -> list[Finding]:
        findings: list[Finding] = []
        for item in failed:
            findings.append(
                make_finding(
                    rule_id="BROKEN001",
                    severity=Severity.ERROR,
                    message="Invalid YAML / unreadable rules file",
                    explanation=item.error,
                    suggestion="Fix YAML syntax so the file can be parsed.",
                    category="broken",
                    file_path=item.path,
                    evidence=(f"error={item.error}",),
                )
            )
        return findings
