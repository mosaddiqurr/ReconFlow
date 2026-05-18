"""Risk scoring helpers for correlated findings."""

from pathlib import Path
from typing import Any

import yaml

from reconflow.models.finding import Finding


DEFAULT_RISK_RULES_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "rules" / "risk_rules.yaml"
)


def load_risk_rules(rules_path: str | Path | None = None) -> dict[str, Any]:
    """Load risk scoring rules from YAML."""
    path = Path(rules_path) if rules_path is not None else DEFAULT_RISK_RULES_PATH
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def get_finding_rule(
    rule_id: str,
    rules: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a named finding rule, or an empty rule if it is unknown."""
    rule_set = rules if rules is not None else load_risk_rules()
    return dict(rule_set.get("finding_rules", {}).get(rule_id, {}))


def severity_score(
    severity: str,
    rules: dict[str, Any] | None = None,
) -> int:
    """Return the default score for a severity label."""
    rule_set = rules if rules is not None else load_risk_rules()
    scores = rule_set.get("severity_scores", {})
    return _clamp_score(scores.get(severity.lower(), 0))


def score_for_rule(
    rule_id: str,
    severity: str | None = None,
    rules: dict[str, Any] | None = None,
) -> int:
    """Return the configured score for a rule, with optional severity override."""
    rule_set = rules if rules is not None else load_risk_rules()
    rule = get_finding_rule(rule_id, rule_set)
    normalized_severity = severity.lower() if severity else None
    severity_overrides = rule.get("severity_scores", {})
    if normalized_severity in severity_overrides:
        return _clamp_score(severity_overrides[normalized_severity])
    if "risk_score" in rule:
        return _clamp_score(rule["risk_score"])
    if normalized_severity:
        return severity_score(normalized_severity, rule_set)
    return 0


def calculate_overall_risk_score(
    findings: list[Finding],
    rules: dict[str, Any] | None = None,
) -> int:
    """Calculate an overall attack surface risk score from 0 to 100."""
    if not findings:
        return 0

    rule_set = rules if rules is not None else load_risk_rules()
    overall_rules = rule_set.get("overall_risk", {})
    max_score = max(finding.risk_score for finding in findings)
    additional_finding_bonus = int(overall_rules.get("per_additional_finding_bonus", 3))
    high_or_critical_bonus = int(overall_rules.get("high_or_critical_bonus", 8))
    exposed_database_bonus = int(overall_rules.get("exposed_database_bonus", 5))

    score = max_score + (len(findings) - 1) * additional_finding_bonus
    if any(finding.severity.lower() in {"high", "critical"} for finding in findings):
        score += high_or_critical_bonus
    if any(finding.title == "Open database/service port" for finding in findings):
        score += exposed_database_bonus

    return _clamp_score(score)


def score_findings(findings: list[dict]) -> list[dict]:
    """Attach risk scores to dictionaries that contain a rule_id or severity."""
    rules = load_risk_rules()
    scored = []
    for finding in findings:
        item = dict(finding)
        rule_id = str(item.get("rule_id", ""))
        severity = str(item.get("severity", "")).lower()
        if "risk_score" not in item:
            item["risk_score"] = (
                score_for_rule(rule_id, severity, rules)
                if rule_id
                else severity_score(severity, rules)
            )
        scored.append(item)
    return scored


def _clamp_score(value: Any) -> int:
    try:
        score = int(value)
    except (TypeError, ValueError):
        return 0
    return max(0, min(100, score))
