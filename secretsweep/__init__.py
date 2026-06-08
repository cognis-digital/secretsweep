"""SECRETSWEEP — zero-install secret scanner (gitleaks/trufflehog-style).

Bundled provider regex pack (50+ secret types), Shannon-entropy detection,
an allowlist layer, inline allow comments and a baseline for CI. Standard
library only.
"""

from .core import (
    TOOL_NAME,
    TOOL_VERSION,
    SEVERITY_ORDER,
    RULES,
    Rule,
    Allowlist,
    Engine,
    Finding,
    shannon_entropy,
    rule_by_id,
    sort_findings,
    summarize,
    load_config,
    load_baseline,
    write_baseline,
    DEFAULT_STOPWORDS,
)

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "SEVERITY_ORDER",
    "RULES",
    "Rule",
    "Allowlist",
    "Engine",
    "Finding",
    "shannon_entropy",
    "rule_by_id",
    "sort_findings",
    "summarize",
    "load_config",
    "load_baseline",
    "write_baseline",
    "DEFAULT_STOPWORDS",
]
