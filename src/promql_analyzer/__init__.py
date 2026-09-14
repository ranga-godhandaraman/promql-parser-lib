"""PromQL Analyzer — static analysis toolkit for PromQL queries.

Public API
----------
Primary entry points:

* ``analyze`` — analyze a PromQL query
* ``analyze_file`` / ``analyze_yaml_file`` — analyze ``.promql`` or rule YAML files
* ``AnalyzerConfig`` — configuration for rules and scoring
* ``AnalysisResult`` — structured result with findings, complexity, explanations
* ``PromQLSyntaxError`` / ``InvalidPromQL`` — invalid query errors

Example::

    from promql_analyzer import analyze, analyze_file, AnalyzerConfig

    result = analyze("sum(rate(http_requests_total[5m]))")
    print(result.structure.metrics)
    print(result.findings)
    print(result.complexity.score)
    print(result.explain())

    report = analyze_file("alerts.yaml")
    for item in report.queries:
        print(item.source.rule_name, item.result.findings if item.result else item.error)
"""

from promql_analyzer.analyze import analyze
from promql_analyzer.files import (
    ExtractedQuery,
    FileAnalysisReport,
    FileQueryResult,
    analyze_file,
    analyze_yaml_file,
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
from promql_analyzer.serialize import result_to_dict

__all__ = [
    "Aggregation",
    "AnalysisResult",
    "AnalyzerConfig",
    "ComplexityFactor",
    "ComplexityLevel",
    "ComplexityResult",
    "ComplexityThresholds",
    "ComplexityWeights",
    "Explanation",
    "ExtractedQuery",
    "FileAnalysisReport",
    "FileQueryResult",
    "Finding",
    "InvalidPromQL",
    "LabelMatcher",
    "PromQLSyntaxError",
    "QueryFeatures",
    "QueryStructure",
    "Severity",
    "analyze",
    "analyze_file",
    "analyze_yaml_file",
    "result_to_dict",
]

__version__ = "0.1.0"
