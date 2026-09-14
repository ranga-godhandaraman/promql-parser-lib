# PromQL Analyzer — Project Intention

## 1. What is this project?

**PromQL Analyzer** is an open-source Python package for understanding, analyzing, and improving PromQL queries.

It is designed to analyze an **existing PromQL query** and provide useful, structured feedback about:

- What the query contains
- How the query is structurally composed
- Potentially suspicious patterns
- Static analysis findings
- Structural complexity
- A human-readable explanation of what the query does

The project can be thought of as:

> **A static analysis and intelligence toolkit for PromQL.**

A useful analogy is:

> **Ruff/Pylint-style analysis for PromQL, combined with query explanation.**

---

# 2. Why does this project exist?

PromQL is powerful, but queries can quickly become difficult to:

- Read
- Understand
- Review
- Maintain
- Debug
- Validate

For example:

```promql
sum by(namespace)(
  rate(
    http_requests_total{
      status=~"5.."
    }[5m]
  )
)
```

An experienced Prometheus user may understand this quickly.

A beginner or someone reviewing another person's query may need to determine:

- Which metric is being queried?
- Which labels are being filtered?
- What does `=~"5.."` mean?
- What does `rate()` do?
- What does `[5m]` represent?
- What is being aggregated?
- What does `by(namespace)` change?
- Is there anything suspicious about the query?
- How structurally complex is the query?

PromQL Analyzer aims to make this process easier.

---

# 3. The core problem we are solving

The problem is NOT:

> "How can we generate PromQL queries?"

The problem is:

> "How can we understand and analyze PromQL queries that already exist?"

A user may receive a PromQL query from:

- Another engineer
- An existing alert
- A Grafana dashboard
- A Prometheus rule
- Documentation
- An incident investigation
- A GitHub repository

They should be able to give that query to PromQL Analyzer and receive meaningful analysis.

Example:

```python
from promql_analyzer import analyze

result = analyze(
    'sum by(namespace)(rate(http_requests_total{status=~"5.."}[5m]))'
)
```

The result should help answer:

1. What does this query contain?
2. How is it structured?
3. Are there suspicious patterns?
4. How complex is it?
5. What does it do in plain language?

---

# 4. What PromQL Analyzer IS

PromQL Analyzer is intended to be:

## 4.1 A structural analyzer

It should understand the structure of a PromQL query.

For example:

```promql
sum by(namespace)(
  rate(
    http_requests_total{
      status=~"5.."
    }[5m]
  )
)
```

It should be able to identify:

### Metrics

```text
http_requests_total
```

### Functions

```text
sum
rate
```

### Label matchers

```text
status =~ "5.."
```

### Range vectors

```text
5m
```

### Aggregations

```text
sum by(namespace)
```

The analyzer should understand the query structurally, preferably through a real PromQL parser or AST rather than fragile regular expressions.

---

## 4.2 A static analyzer

The package should inspect a query for patterns that may deserve attention.

Examples include:

### Suspicious counter usage

```promql
avg(http_requests_total)
```

Possible finding:

```text
WARNING PQL001

This metric appears to be a counter based on the `_total` suffix.

Counters are commonly used with functions such as rate(),
irate(), or increase().
```

The analyzer should not claim that the query is invalid unless it can know that with confidence.

---

### Broad regex matching

```promql
pod=~".*"
```

Possible finding:

```text
WARNING PQL002

A broad regex matcher was detected.

This pattern may increase query cost depending on the number
of matching time series.
```

---

### Suspicious rate window

```promql
rate(metric[10s])
```

Possible finding:

```text
WARNING

The selected range window may be short relative to the
configured scrape interval.

This is a heuristic finding.
```

---

### High-cardinality grouping

```promql
sum by(
  pod,
  container,
  instance,
  request_id
)(
  rate(metric[5m])
)
```

Possible finding:

```text
WARNING

A large number of grouping labels was detected.

This may increase the number of resulting time series.
```

---

# 5. What PromQL Analyzer is NOT

Clear boundaries are important.

PromQL Analyzer is NOT:

## 5.1 A PromQL query builder

It should not focus on generating queries like:

```python
Query("http_requests_total").rate("5m").sum()
```

There are already tools and patterns for query construction.

Our primary focus is analyzing existing queries.

---

## 5.2 A Prometheus replacement

PromQL Analyzer will not:

- Store metrics
- Scrape targets
- Execute PromQL like Prometheus
- Replace Prometheus
- Replace Grafana

It analyzes query text.

---

## 5.3 A runtime query profiler

Without access to a real Prometheus environment, the package cannot know:

- Actual series cardinality
- Storage backend behavior
- Prometheus hardware
- Query engine state
- Recording rules
- Data distribution

Therefore it must never claim:

> "This query will definitely be slow."

Instead:

> "This pattern may increase query cost depending on runtime conditions."

The analyzer performs **static analysis and heuristics**, not runtime profiling.

---

## 5.4 An AI-first project

The core package should work without:

- LLMs
- External AI APIs
- Vector databases
- Embeddings
- Cloud AI services

Analysis should initially be:

- Deterministic
- Testable
- Explainable
- Offline-capable

AI may be considered in the distant future, but it is not part of the core project.

---

# 6. The intended analysis flow

The architecture should follow a clear pipeline.

```text
                 PromQL Query
                      │
                      ▼
                   Parser
                      │
                      ▼
                 AST / Tree
                      │
                      ▼
            Structural Analysis
                      │
                      ▼
               Rule Analysis
                      │
                      ▼
             Complexity Analysis
                      │
                      ▼
              Explanation Engine
                      │
                      ▼
              Analysis Result
```

Each stage has a separate responsibility.

---

# 7. Stage 1 — Parsing

Input:

```promql
sum(rate(http_requests_total[5m]))
```

The parser should understand PromQL syntax and produce a structure that later stages can inspect.

Important principle:

> The project should avoid reimplementing PromQL unnecessarily.

Before building a custom parser, existing PromQL parsing libraries, grammars, or reliable integrations should be evaluated.

The innovation of this project is primarily:

> **Analysis**

not:

> **Recreating Prometheus parsing from scratch.**

---

# 8. Stage 2 — Structural Analysis

The structural analysis layer answers:

> "What is inside this query?"

It should extract information such as:

- Metrics
- Functions
- Aggregations
- Grouping labels
- Label matchers
- Range vectors
- Binary operators
- Nested functions
- Subqueries when supported
- Offset modifiers
- `@` modifiers

Example:

```promql
sum by(namespace)(
  rate(
    http_requests_total{
      status=~"5.."
    }[5m]
  )
)
```

Could conceptually produce:

```text
Metrics:
- http_requests_total

Functions:
- sum
- rate

Label Matchers:
- status =~ "5.."

Range Vectors:
- 5m

Aggregation:
- sum by(namespace)

Features:
- aggregation
- regex matcher
- nested function
```

This layer should describe facts about the query.

It should avoid subjective judgments.

---

# 9. Stage 3 — Static Analysis

The static analysis layer answers:

> "Is there anything in this query that deserves attention?"

This layer uses independent rules.

Conceptually:

```text
Query Structure
      │
      ▼
   Rule Engine
      │
 ┌────┼────┐
 ▼    ▼    ▼
Rule Rule Rule
 1    2    3
 │    │    │
 └────┼────┘
      ▼
   Findings
```

Each rule should:

- Have a stable rule ID
- Be independently testable
- Return zero or more findings
- Explain why something was flagged
- Provide a suggestion when appropriate

Example rule IDs:

```text
PQL001
PQL002
PQL003
```

The exact rules can evolve.

---

# 10. Finding severity

Findings should distinguish between confidence and severity.

Initial severities:

```text
ERROR
WARNING
INFO
```

Important principle:

## ERROR

Use when something is structurally or syntactically incorrect according to reliable knowledge.

## WARNING

Use when a pattern may cause problems or deserves review.

## INFO

Use for observations or low-risk recommendations.

The analyzer should avoid treating heuristics as errors.

---

# 11. Stage 4 — Complexity Analysis

PromQL Analyzer should calculate a **structural complexity score**.

This is NOT a runtime performance score.

The score should represent how difficult the query is structurally.

Possible factors:

- Number of functions
- Function nesting depth
- Number of label matchers
- Regex matchers
- Number of grouping labels
- Binary operators
- Subqueries
- Offset modifiers
- `@` modifiers

Example:

```promql
up
```

May have low complexity.

```promql
sum(rate(http_requests_total[5m]))
```

May have moderate complexity.

```promql
histogram_quantile(
  0.95,
  sum by(le, service)(
    rate(
      http_request_duration_seconds_bucket{
        service=~"api-.*"
      }[5m]
    )
  )
)
```

May have higher structural complexity.

The result should be transparent.

Example:

```text
Complexity Score: 62 / 100

Factors:

+10 Nested functions
+10 Multiple functions
+5 Regex matcher
+10 Aggregation
+10 Grouping labels
```

Users should be able to understand why a score was produced.

---

# 12. Stage 5 — Explanation Engine

The explanation engine answers:

> "What does this query do?"

Example input:

```promql
sum by(namespace)(
  rate(
    http_requests_total{
      status=~"5.."
    }[5m]
  )
)
```

Possible output:

```text
This query selects the metric `http_requests_total`
for series where the `status` label matches 5xx values.

It calculates the per-second rate of increase over
the previous 5 minutes.

It then sums the resulting series while keeping
separate results for each namespace.
```

The explanation must be:

- Deterministic
- Derived from query structure
- Technically accurate
- Understandable to beginners

It should not invent metric meaning.

For example:

```text
my_custom_metric
```

should not automatically be described as:

```text
CPU usage
```

unless the analyzer has reliable context.

---

# 13. The core output

The package should return a structured result.

Conceptually:

```python
AnalysisResult(
    structure=...,
    findings=[...],
    complexity=...,
    explanation=...
)
```

A user should be able to inspect:

```python
result.structure

result.findings

result.complexity

result.explain()
```

The exact API may evolve, but the public API should remain small and intuitive.

---

# 14. Intended users

PromQL Analyzer should be useful for several groups.

## Beginners

They can understand complex queries.

Example:

```text
What does this query do?
```

---

## DevOps / Platform Engineers

They can review:

- Alert queries
- Recording rules
- Dashboards

---

## Code Review

PromQL can be analyzed as part of a pull request.

Potential future flow:

```text
Pull Request
      │
      ▼
PromQL File Changed
      │
      ▼
PromQL Analyzer
      │
      ▼
Findings
```

---

## CI/CD

Potential future use:

```bash
promql-analyze alerts/
```

Output:

```text
18 queries analyzed

16 passed
2 warnings
0 errors
```

---

# 15. Python API

The primary API should remain simple.

Example:

```python
from promql_analyzer import analyze

result = analyze(
    'sum(rate(http_requests_total[5m]))'
)
```

With configuration:

```python
from promql_analyzer import analyze, AnalyzerConfig

config = AnalyzerConfig(
    scrape_interval_seconds=15
)

result = analyze(
    query,
    config=config
)
```

Users should not need to understand internal architecture to use the package.

---

# 16. CLI

The project should eventually provide a CLI.

Example:

```bash
promql-analyze analyze 'sum(rate(http_requests_total[5m]))'
```

Example output:

```text
PROMQL ANALYSIS

Structure

Metric:
http_requests_total

Functions:
sum
rate

Range:
5m


Findings

No major findings.


Complexity

25 / 100
MODERATE


Explanation

This query calculates the rate of increase of
http_requests_total over the previous 5 minutes
and sums the resulting series.
```

---

# 17. Design principles

The project should follow these principles.

## 17.1 Accuracy over cleverness

Do not produce impressive but unreliable analysis.

---

## 17.2 Explainability over magic

Every finding should explain:

- What was detected
- Why it matters
- How confident the analyzer is when relevant

---

## 17.3 Static facts vs heuristics

Keep these separate.

### Fact

```text
The query contains two functions.
```

### Heuristic

```text
The query may be difficult to maintain because it has deep nesting.
```

Never present a heuristic as a fact.

---

## 17.4 Simple architecture

Avoid unnecessary:

- Microservices
- Databases
- Web servers
- Plugin frameworks
- AI infrastructure
- Kubernetes dependencies

This should remain a Python package.

---

## 17.5 Extensibility without over-engineering

Rules should be independently testable.

New analysis capabilities should not require rewriting the core.

But do not build complicated extension systems before they are needed.

---

## 17.6 Offline-first

Core analysis should work locally.

A developer should be able to run:

```bash
promql-analyze query.promql
```

without requiring:

- Cloud services
- API keys
- Internet access

---

# 18. Project boundaries for V1

V1 should focus on:

## Parsing

Use or integrate a reliable PromQL parser.

## Structural analysis

Extract important query components.

## Static rules

Implement a small number of useful rules.

## Complexity

Provide a transparent structural complexity score.

## Explanation

Generate deterministic human-readable explanations.

## Python API

Provide a clean import and analysis function.

## CLI

Allow command-line analysis.

---

# 19. Things explicitly excluded from V1

Do not add:

- AI
- LLM integration
- Kubernetes APIs
- Prometheus server integration
- Grafana integration
- Databases
- Web dashboards
- VS Code extensions
- GitHub Actions
- Runtime query profiling
- Automatic query rewriting

These may be evaluated later.

They should not block the first release.

---

# 20. Long-term possibilities

After a stable V1, possible directions include:

## CI integration

Analyze PromQL during pull requests.

## Pre-commit integration

Prevent problematic queries from entering a repository.

## Editor integration

Provide explanations and findings inside an IDE.

## Prometheus rule analysis

Analyze complete alerting and recording rule files.

## Query comparison

Compare two PromQL queries structurally.

## Query refactoring suggestions

Provide safe suggestions for improving readability.

These are ideas, not current requirements.

---

# 21. The most important principle

Before adding a feature, ask:

> Does this help a developer understand, analyze, validate, or improve an existing PromQL query?

If the answer is no, the feature probably does not belong in the core package.

This question should protect the project from scope creep.

---

# 22. Project mission

The mission of PromQL Analyzer is:

> **Make PromQL queries easier to understand, review, and reason about through reliable structural analysis, transparent static analysis, and clear explanations.**

---

# 23. One-sentence explanation

If someone asks:

> "What is PromQL Analyzer?"

The answer is:

> **PromQL Analyzer is an open-source Python package that analyzes existing PromQL queries, explains how they work, identifies potentially problematic patterns, and provides transparent structural complexity insights.**

---

# 24. Short project flow

```text
Existing PromQL Query
        │
        ▼
      Parse
        │
        ▼
Understand Structure
        │
        ▼
Apply Static Rules
        │
        ▼
Calculate Structural Complexity
        │
        ▼
Generate Explanation
        │
        ▼
Return Useful Analysis
```

---

# 25. Final reminder

This project should start small.

The goal is not to build:

> "The ultimate observability platform."

The goal is to build:

> **One reliable tool that helps people understand and improve PromQL queries.**

Start with a small, useful V1.

Ship it.

Get feedback.

Then evolve based on real user problems.

---

**Project status:** Intention and scope definition

**Current focus:** Core PromQL static analysis

**Primary language:** Python

**Primary principle:** Understand existing PromQL before trying to generate or execute it
