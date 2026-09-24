"""``dude_rushup.vuln()`` — potential security exposure scanning."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from promql_analyzer.dude_rushup._base import (
    make_finding,
    rebuild_report,
    risk_to_severity,
)
from promql_analyzer.dude_rushup.context import AnalysisContext
from promql_analyzer.dude_rushup.inventory import build_inventory
from promql_analyzer.models import Finding
from promql_analyzer.repository.models import (
    RepositoryReport,
    RepositoryScanConfig,
    RuleRecord,
)

# High-confidence secret patterns (static *potential* exposure indicators).
_AWS_ACCESS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
_URL_WITH_USERINFO = re.compile(
    r"(?i)\bhttps?://[^/\s:@]+:[^/\s:@]+@[^\s\"']+"
)
_GENERIC_ASSIGNMENT = re.compile(
    r"(?i)\b(api[_-]?key|apikey|secret|password|passwd|token|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token)\b\s*[:=]\s*([^\s,;\"']{8,})"
)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*")

_PLACEHOLDER = re.compile(
    r"(?i)^(true|false|null|none|changeme|change.?me|xxx+|todo|replace.?me|"
    r"<[^>]+>|\$\{[^}]+\}|\{\{[^}]+\}\}|example|dummy|test|password|secret)$"
)


@dataclass(frozen=True)
class VulnConfig:
    """Configuration for potential security-risk scanning."""

    scan_labels: bool = True
    scan_annotations: bool = True
    scan_expr: bool = False  # exprs rarely hold secrets; off by default
    min_secret_length: int = 8
    scan: RepositoryScanConfig = field(
        default_factory=lambda: RepositoryScanConfig(
            analyze_promql=False,
            enrich_findings=False,
        )
    )


def vuln(
    path: Path | str,
    config: VulnConfig | None = None,
    *,
    scan_config: RepositoryScanConfig | None = None,
    context: AnalysisContext | None = None,
) -> RepositoryReport:
    """Scan alert/rule repositories for potential security exposures.

    Findings indicate *possible* risk from static inspection. They are not
    confirmed vulnerabilities.
    """
    cfg = config if config is not None else VulnConfig()
    effective_scan = scan_config if scan_config is not None else cfg.scan
    ctx = context or AnalysisContext.from_path(path, scan_config=effective_scan)
    analyzer = VulnAnalyzer(cfg)
    findings = analyzer.analyze_report(ctx.report)
    inventory = build_inventory(ctx.report.alerts, ctx.report.recording_rules)
    return rebuild_report(ctx.report, findings, inventory=inventory)


class VulnAnalyzer:
    """Detect potential secrets and sensitive values in rule metadata."""

    def __init__(self, config: VulnConfig | None = None) -> None:
        self.config = config if config is not None else VulnConfig()

    def analyze_report(self, report: RepositoryReport) -> list[Finding]:
        findings: list[Finding] = []
        for rule in report.rules:
            findings.extend(self.analyze_rule(rule))
        return findings

    def analyze_rule(self, rule: RuleRecord) -> list[Finding]:
        findings: list[Finding] = []
        if self.config.scan_labels:
            for key, value in rule.labels:
                findings.extend(
                    self._scan_text(
                        value,
                        field_name=f"labels.{key}",
                        rule=rule,
                        key_hint=key,
                    )
                )
        if self.config.scan_annotations:
            for key, value in rule.annotations:
                findings.extend(
                    self._scan_text(
                        value,
                        field_name=f"annotations.{key}",
                        rule=rule,
                        key_hint=key,
                    )
                )
        if self.config.scan_expr and rule.expr:
            findings.extend(
                self._scan_text(
                    rule.expr,
                    field_name="promql",
                    rule=rule,
                    key_hint="promql",
                )
            )
        return findings

    def _scan_text(
        self,
        text: str,
        *,
        field_name: str,
        rule: RuleRecord,
        key_hint: str,
    ) -> list[Finding]:
        if not text or _is_placeholder(text):
            return []

        findings: list[Finding] = []

        if _PRIVATE_KEY.search(text):
            findings.append(
                self._finding(
                    level="CRITICAL",
                    rule_id="VULN001",
                    message="Possible private key material in rule metadata",
                    explanation=(
                        f"Field {field_name} appears to contain PEM private key "
                        "material. This is a potential credential exposure risk."
                    ),
                    suggestion="Remove private keys from alert labels/annotations.",
                    rule=rule,
                    field_name=field_name,
                    pattern="private_key",
                )
            )

        if _AWS_ACCESS_KEY.search(text):
            findings.append(
                self._finding(
                    level="HIGH",
                    rule_id="VULN002",
                    message="Possible AWS access key id in rule metadata",
                    explanation=(
                        f"Field {field_name} matches an AWS access key id pattern. "
                        "Static analysis indicates potential exposure, not a confirmed leak."
                    ),
                    suggestion="Rotate the key if real and remove it from rule YAML.",
                    rule=rule,
                    field_name=field_name,
                    pattern="aws_access_key",
                )
            )

        if _URL_WITH_USERINFO.search(text):
            findings.append(
                self._finding(
                    level="HIGH",
                    rule_id="VULN003",
                    message="Possible credentials embedded in URL",
                    explanation=(
                        f"Field {field_name} contains a URL with userinfo "
                        "(`user:pass@host`), which may embed secrets."
                    ),
                    suggestion="Remove embedded credentials from URLs.",
                    rule=rule,
                    field_name=field_name,
                    pattern="url_userinfo",
                )
            )

        if _JWT.search(text):
            findings.append(
                self._finding(
                    level="HIGH",
                    rule_id="VULN004",
                    message="Possible JWT/token value in rule metadata",
                    explanation=(
                        f"Field {field_name} looks like a JWT. This may be a "
                        "sensitive token accidentally committed to rules."
                    ),
                    suggestion="Remove tokens from labels/annotations; use references instead.",
                    rule=rule,
                    field_name=field_name,
                    pattern="jwt",
                )
            )

        if _BEARER.search(text):
            findings.append(
                self._finding(
                    level="HIGH",
                    rule_id="VULN005",
                    message="Possible Bearer token in rule metadata",
                    explanation=(
                        f"Field {field_name} contains a Bearer token-like value."
                    ),
                    suggestion="Remove bearer tokens from alert metadata.",
                    rule=rule,
                    field_name=field_name,
                    pattern="bearer",
                )
            )

        for match in _GENERIC_ASSIGNMENT.finditer(text):
            secret_value = match.group(2)
            if len(secret_value) < self.config.min_secret_length:
                continue
            if _is_placeholder(secret_value):
                continue
            findings.append(
                self._finding(
                    level="MEDIUM",
                    rule_id="VULN006",
                    message=f"Possible secret assignment in {field_name}",
                    explanation=(
                        f"Field {field_name} contains a credential-like assignment "
                        f"({match.group(1)}=...). This is a potential exposure risk."
                    ),
                    suggestion="Remove secrets from rule YAML; reference a secret store.",
                    rule=rule,
                    field_name=field_name,
                    pattern="assignment",
                )
            )

        # Sensitive key names with long opaque values.
        if _looks_sensitive_key(key_hint) and _looks_opaque_secret(
            text, self.config.min_secret_length
        ):
            findings.append(
                self._finding(
                    level="MEDIUM",
                    rule_id="VULN007",
                    message=f"Sensitive key {key_hint!r} has opaque value",
                    explanation=(
                        f"Field {field_name} uses a credential-like key name with an "
                        "opaque value. This may be an accidentally embedded secret."
                    ),
                    suggestion="Confirm the value is not a live secret; remove if it is.",
                    rule=rule,
                    field_name=field_name,
                    pattern="sensitive_key",
                )
            )

        return findings

    def _finding(
        self,
        *,
        level: str,
        rule_id: str,
        message: str,
        explanation: str,
        suggestion: str,
        rule: RuleRecord,
        field_name: str,
        pattern: str,
    ) -> Finding:
        return make_finding(
            rule_id=rule_id,
            severity=risk_to_severity(level),
            message=f"{message} [{level} potential risk]",
            explanation=explanation
            + " Static analysis cannot confirm this is a live vulnerability.",
            suggestion=suggestion,
            category="vuln",
            file_path=rule.file_path,
            rule_name=rule.name,
            score={"LOW": 1.0, "MEDIUM": 2.0, "HIGH": 3.0, "CRITICAL": 4.0}[level],
            evidence=(
                f"risk_level={level}",
                f"field={field_name}",
                f"pattern={pattern}",
            ),
        )


def _is_placeholder(text: str) -> bool:
    stripped = text.strip().strip("'\"")
    if not stripped:
        return True
    if _PLACEHOLDER.match(stripped):
        return True
    if stripped.startswith("{{") and stripped.endswith("}}"):
        return True
    return False


def _looks_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    needles = (
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "access_key",
        "private_key",
        "credential",
        "auth",
    )
    return any(n in lowered for n in needles)


def _looks_opaque_secret(text: str, min_length: int) -> bool:
    stripped = text.strip().strip("'\"")
    if len(stripped) < min_length:
        return False
    if _is_placeholder(stripped):
        return False
    # Prefer values that look random/opaque rather than prose.
    if " " in stripped and len(stripped.split()) > 3:
        return False
    alnum = sum(ch.isalnum() for ch in stripped)
    return (alnum / len(stripped)) >= 0.7
