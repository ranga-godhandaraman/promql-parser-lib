"""Unified configuration for ``dude_rushup`` analyzers."""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from promql_analyzer.dude_rushup.broken import BrokenConfig
from promql_analyzer.dude_rushup.noise_models import NoiseRiskConfig
from promql_analyzer.dude_rushup.secuch import SecuchConfig
from promql_analyzer.dude_rushup.speakup_models import SpeakupConfig
from promql_analyzer.dude_rushup.vuln import VulnConfig
from promql_analyzer.models import AnalyzerConfig
from promql_analyzer.repository.models import RepositoryScanConfig


@dataclass(frozen=True)
class RushupConfig:
    """Coherent V2 configuration with sensible defaults.

    Covers discovery, noise-risk, broken-rule checks, vuln/secuch policies,
    and speakup optimization analysis. Nested configs keep analyzer-specific
    knobs while top-level fields provide a single place for common settings.
    """

    # Discovery / include-exclude
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

    # Which analyzers run under comeup_360 / multi-select CLI.
    enable_wild: bool = True
    enable_broken: bool = True
    enable_vuln: bool = True
    enable_secuch: bool = True
    enable_speakup: bool = True

    # Nested analyzer configs (defaults are safe / low false-positive).
    wild: NoiseRiskConfig = field(default_factory=NoiseRiskConfig)
    broken: BrokenConfig = field(default_factory=BrokenConfig)
    vuln: VulnConfig = field(default_factory=VulnConfig)
    secuch: SecuchConfig = field(default_factory=SecuchConfig)
    speakup: SpeakupConfig = field(default_factory=SpeakupConfig)

    # Shared PromQL analyzer settings used by speakup / optional lint reuse.
    analyzer: AnalyzerConfig = field(default_factory=AnalyzerConfig)

    def to_scan_config(self) -> RepositoryScanConfig:
        """Build the discovery config used by the shared pipeline."""
        return RepositoryScanConfig(
            include_globs=self.include_globs,
            exclude_globs=self.exclude_globs,
            follow_symlinks=self.follow_symlinks,
            analyze_promql=False,
            enrich_findings=False,
        )

    def with_analyzers(
        self,
        *,
        wild: bool | None = None,
        broken: bool | None = None,
        vuln: bool | None = None,
        secuch: bool | None = None,
        speakup: bool | None = None,
    ) -> RushupConfig:
        """Return a copy with analyzer enable flags updated."""
        return replace(
            self,
            enable_wild=self.enable_wild if wild is None else wild,
            enable_broken=self.enable_broken if broken is None else broken,
            enable_vuln=self.enable_vuln if vuln is None else vuln,
            enable_secuch=self.enable_secuch if secuch is None else secuch,
            enable_speakup=self.enable_speakup if speakup is None else speakup,
        )

    def resolved_wild(self) -> NoiseRiskConfig:
        return replace(self.wild, scan=self.to_scan_config())

    def resolved_broken(self) -> BrokenConfig:
        broken = self.broken
        # Propagate common required-label knobs if broken config is empty and
        # secuch already defines policy labels — keep them independent by default.
        return replace(broken, scan=self.to_scan_config())

    def resolved_vuln(self) -> VulnConfig:
        return replace(self.vuln, scan=self.to_scan_config())

    def resolved_secuch(self) -> SecuchConfig:
        return replace(self.secuch, scan=self.to_scan_config())

    def resolved_speakup(self) -> SpeakupConfig:
        speakup = self.speakup
        analyzer = (
            speakup.analyzer_config
            if speakup.analyzer_config is not None
            else self.analyzer
        )
        return replace(speakup, analyzer_config=analyzer, scan=self.to_scan_config())


# Backward-friendly alias used in docs / comeup_360 signature.
Comeup360Config = RushupConfig
