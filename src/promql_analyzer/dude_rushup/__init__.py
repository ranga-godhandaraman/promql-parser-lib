"""V2 repository analyzers under the ``dude_rushup`` namespace.

Implemented:

* ``wild`` — static alert noise-risk scoring
* ``broken`` — incomplete / invalid rule detection
* ``vuln`` — potential security exposure scanning
* ``secuch`` — configurable security policy / hygiene checks
* ``speakup`` — PromQL optimization recommendations
* ``comeup_360`` — run all analyzers on one shared scan
"""

from promql_analyzer.dude_rushup.broken import BrokenAnalyzer, BrokenConfig, broken
from promql_analyzer.dude_rushup.comeup_360 import comeup_360, run_analyzers
from promql_analyzer.dude_rushup.config import Comeup360Config, RushupConfig
from promql_analyzer.dude_rushup.context import AnalysisContext
from promql_analyzer.dude_rushup.inventory import RepositoryInventory
from promql_analyzer.dude_rushup.noise import NoiseRiskAnalyzer
from promql_analyzer.dude_rushup.noise_models import (
    DimensionScore,
    NoiseRiskAssessment,
    NoiseRiskConfig,
    NoiseRiskSummary,
)
from promql_analyzer.dude_rushup.secuch import SecuchAnalyzer, SecuchConfig, secuch
from promql_analyzer.dude_rushup.speakup import SpeakupAnalyzer, speakup
from promql_analyzer.dude_rushup.speakup_models import SpeakupConfig, SpeakupSuggestion
from promql_analyzer.dude_rushup.vuln import VulnAnalyzer, VulnConfig, vuln
from promql_analyzer.dude_rushup.wild import wild

__all__ = [
    "AnalysisContext",
    "BrokenAnalyzer",
    "BrokenConfig",
    "Comeup360Config",
    "DimensionScore",
    "NoiseRiskAnalyzer",
    "NoiseRiskAssessment",
    "NoiseRiskConfig",
    "NoiseRiskSummary",
    "RepositoryInventory",
    "RushupConfig",
    "SecuchAnalyzer",
    "SecuchConfig",
    "SpeakupAnalyzer",
    "SpeakupConfig",
    "SpeakupSuggestion",
    "VulnAnalyzer",
    "VulnConfig",
    "broken",
    "comeup_360",
    "run_analyzers",
    "secuch",
    "speakup",
    "vuln",
    "wild",
]
