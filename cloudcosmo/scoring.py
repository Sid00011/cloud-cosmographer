"""
Scoring engine. Deliberately reuses the same model as zparty's scoring/engine.py
(severity penalties capped per rule type, S-to-E letter grade) so the two tools
share one risk vocabulary whether the target is a web app or a cloud account.
"""
from __future__ import annotations

SEVERITY_PENALTIES = {"Critical": 40, "High": 20, "Medium": 8, "Low": 3, "Info": 0}
CAP_MULTIPLIER = 2  # each rule_id deducts at most (2 * penalty), regardless of count
GRADES = [("S", 90), ("A", 75), ("B", 60), ("C", 45), ("D", 30), ("E", 0)]


def grade_for(score: int) -> str:
    for letter, threshold in GRADES:
        if score >= threshold:
            return letter
    return "E"


def score_findings(findings) -> dict:
    score = 100
    by_rule: dict[str, int] = {}
    for f in findings:
        by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1

    deductions = {}
    for rule_id, count in by_rule.items():
        sample = next(f for f in findings if f.rule_id == rule_id)
        penalty = SEVERITY_PENALTIES.get(sample.severity, 0)
        capped = min(count, CAP_MULTIPLIER) * penalty
        deductions[rule_id] = capped
        score -= capped

    score = max(score, 0)
    return {"score": score, "grade": grade_for(score), "deductions": deductions,
            "total_findings": len(findings)}
