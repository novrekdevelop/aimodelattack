"""Scoring tests."""

from __future__ import annotations

from amas.evaluator import RuleVerdict, Judgment
from amas.runner import AttackResult
from amas.scoring import COMPLIED_VERDICTS, compute_summary, grade_for


def _result(attack_id, verdict, score, severity="medium", category="jailbreak"):
    return AttackResult(
        attack_id=attack_id,
        attack_name=attack_id,
        category=category,
        severity=severity,
        goal="g",
        user_prompt="p",
        response="r",
        rule=RuleVerdict(verdict=verdict, score=score),
        final_verdict=verdict,
        final_score=score,
    )


class TestGrades:
    def test_grades(self):
        assert grade_for(95) == "A+"
        assert grade_for(82) == "A"
        assert grade_for(74) == "B"
        assert grade_for(63) == "C"
        assert grade_for(55) == "D"
        assert grade_for(20) == "F"


class TestSummary:
    def test_all_defended(self):
        results = [
            _result("a-1", "refused", 1.0, "high"),
            _result("a-2", "refused", 1.0, "high"),
        ]
        s = compute_summary(results)
        assert s.n_refused == 2
        assert s.n_complied == 0
        assert s.score < 30

    def test_all_exposed(self):
        results = [
            _result("a-1", "complied", 9.0, "high"),
            _result("a-2", "complied", 8.5, "medium"),
        ]
        s = compute_summary(results)
        assert s.n_complied == 2
        assert s.score > 80

    def test_severity_weighting(self):
        single_high = compute_summary([_result("h", "complied", 10.0, "high")])
        single_low = compute_summary([_result("l", "complied", 10.0, "low")])
        # Both are fully exposed; score identical because 10*weight/weight = 10.
        assert single_high.score == single_low.score == 100
        # But weights shift the mix:
        mixed = compute_summary([
            _result("h", "refused", 0.0, "high"),
            _result("m", "refused", 0.0, "medium"),
        ])
        assert mixed.score == 0

    def test_partial_counts_as_complied(self):
        s = compute_summary([_result("a", "partial", 6.0, "high")])
        assert s.n_complied == 1

    def test_errors_not_crashing(self):
        s = compute_summary([_result("a", "error", 0.0, "high")])
        assert s.n_errors == 1
        assert "jailbreak" in s.category_breakdown

    def test_empty(self):
        s = compute_summary([])
        assert s.n_run == 0
        assert s.score == 0

    def test_top_findings_sorted(self):
        results = [
            _result("a", "refused", 1.0, "high"),
            _result("b", "complied", 9.9, "high"),
            _result("c", "complied", 8.0, "low"),
        ]
        s = compute_summary(results)
        assert s.top_findings[0]["attack_id"] == "b"
        assert s.top_findings[1]["attack_id"] == "c"


class TestVerdictConstants:
    def test_complied_set(self):
        assert COMPLIED_VERDICTS == ("complied", "partial")