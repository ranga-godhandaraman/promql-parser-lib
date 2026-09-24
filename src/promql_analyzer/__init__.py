"""PromQL Analyzer — static analysis toolkit for PromQL queries.

Public API
----------
Primary entry points:

* ``dude_look`` — analyze a PromQL query string
* ``dude_analyze_promql`` — analyze a ``.promql`` / ``.txt`` file
* ``dude_analyze_yaml`` — analyze PromQL found in a ``.yaml`` file
* ``dude_analyze_yml`` — analyze PromQL found in a ``.yml`` file
* ``dude_analyze_json`` — analyze PromQL found in a ``.json`` file
* ``AnalyzerConfig`` — configuration for rules and scoring
* ``AnalysisResult`` — structured result with findings, complexity, explanations
* ``PromQLSyntaxError`` / ``InvalidPromQL`` — invalid query errors

Structured file helpers discover PromQL from common fields such as ``expr``,
``condition``, ``query``, and ``promql`` (not only Prometheus ``expr``).

Example::

    from promql_analyzer import (
        dude_look,
        dude_analyze_promql,
        dude_analyze_yaml,
        dude_analyze_yml,
        dude_analyze_json,
        AnalyzerConfig,
    )

    result = dude_look("sum(rate(http_requests_total[5m]))")
    print(result.structure.metrics)
    print(result.findings)
    print(result.complexity.score)
    print(result.explain())

    report = dude_analyze_yaml("alerts.yaml")
    for item in report.queries:
        print(item.source.rule_name, item.result.findings if item.result else item.error)
"""

from promql_analyzer.analyze import dude_look
from promql_analyzer.dude_rushup import (
    BrokenConfig,
    Comeup360Config,
    NoiseRiskAnalyzer,
    NoiseRiskAssessment,
    NoiseRiskConfig,
    NoiseRiskSummary,
    RepositoryInventory,
    RushupConfig,
    SecuchConfig,
    SpeakupConfig,
    SpeakupSuggestion,
    VulnConfig,
)
from promql_analyzer.files import (
    ExtractedQuery,
    FileAnalysisReport,
    FileQueryResult,
    dude_analyze_json,
    dude_analyze_promql,
    dude_analyze_yaml,
    dude_analyze_yml,
)
from promql_analyzer.models import (
    Aggregation,
    AnalysisResult,
    AnalyzerConfig,
    ComplexityFactor,
    ComplexityLevel,
    ComplexityResult,
    ComplexityThresholds,
    ComplexityWeights,
    Explanation,
    Finding,
    LabelMatcher,
    QueryFeatures,
    QueryStructure,
    Severity,
)
from promql_analyzer.parser import InvalidPromQL, PromQLSyntaxError
from promql_analyzer.repository import (
    AlertRecord,
    AnalysisSummary,
    FailedFile,
    RepositoryAnalyzer,
    RepositoryReport,
    RepositoryScanConfig,
    RepositoryScanner,
    RuleRecord,
)
from promql_analyzer.serialize import result_to_dict

from . import dude_rushup

__all__ = [
    "Aggregation",
    "AlertRecord",
    "AnalysisResult",
    "AnalysisSummary",
    "AnalyzerConfig",
    "BrokenConfig",
    "Comeup360Config",
    "ComplexityFactor",
    "ComplexityLevel",
    "ComplexityResult",
    "ComplexityThresholds",
    "ComplexityWeights",
    "Explanation",
    "ExtractedQuery",
    "FailedFile",
    "FileAnalysisReport",
    "FileQueryResult",
    "Finding",
    "InvalidPromQL",
    "LabelMatcher",
    "NoiseRiskAnalyzer",
    "NoiseRiskAssessment",
    "NoiseRiskConfig",
    "NoiseRiskSummary",
    "PromQLSyntaxError",
    "QueryFeatures",
    "QueryStructure",
    "RepositoryAnalyzer",
    "RepositoryInventory",
    "RepositoryReport",
    "RepositoryScanConfig",
    "RepositoryScanner",
    "RuleRecord",
    "RushupConfig",
    "SecuchConfig",
    "Severity",
    "SpeakupConfig",
    "SpeakupSuggestion",
    "VulnConfig",
    "dude_analyze_json",
    "dude_analyze_promql",
    "dude_analyze_yaml",
    "dude_analyze_yml",
    "dude_look",
    "dude_rushup",
    "result_to_dict",
]

__version__ = "0.2.0"
