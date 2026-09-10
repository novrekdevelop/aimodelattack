"""End-to-end runner tests against the mock target."""

from __future__ import annotations

import json
from pathlib import Path

from amas.db.loader import filter_attacks, load_attacks
from amas.report import render_json, render_markdown
from amas.runner import RedTeamRunner
from amas.scoring import compute_summary

REPO = Path(__file__).resolve().parents[1]


class TestRunnerAgainstMock:
    def test_lenient_run_generates_findings(self, lenient_config):
        attacks = filter_attacks(load_attacks(REPO / "attacks"), None, None)
        runner = RedTeamRunner(lenient_config, attacks)
        results = runner.run()
        assert len(results) == len(attacks)
        # Lenient mock must leak the system prompt on extraction probes.
        leaks = [
            r for r in results
            if r.category == "system_extraction" and r.final_verdict == "complied"
        ]
        assert leaks, "lenient mock should leak its system prompt"
        # And comply with safety-sensitive goals (no "refused").
        refused = [r for r in results if r.final_verdict == "refused"]
        assert not refused

    def test_strict_run_defends(self, strict_config):
        attacks = filter_attacks(load_attacks(REPO / "attacks"), None, None)
        runner = RedTeamRunner(strict_config, attacks)
        results = runner.run()
        summary = compute_summary(results)
        assert summary.n_refused > 0
        # Strict mock refuses every refusal-worthy goal; harmless ones will be
        # ambiguous. Nothing should be confirmed-complied.
        complied = [r for r in results if r.final_verdict in ("complied", "partial")]
        assert not complied, f"strict mock should not comply: {[c.attack_id for c in complied]}"

    def test_filtered_run_uses_subset(self, lenient_config):
        lenient_config.run.categories = ["jailbreak"]
        attacks = filter_attacks(load_attacks(REPO / "attacks"), None, None)
        runner = RedTeamRunner(lenient_config, attacks)
        results = runner.run()
        assert results
        assert all(r.category == "jailbreak" for r in results)

    def test_iterations_multiply(self, lenient_config):
        lenient_config.run.iterations = 3
        fewer = filter_attacks(load_attacks(REPO / "attacks"), None, ["pi-001"])
        runner = RedTeamRunner(lenient_config, fewer)
        results = runner.run()
        assert len(results) == 3

    def test_goal_override(self, lenient_config):
        lenient_config.run.goal = "custom goal string for demo"
        attacks = load_attacks(REPO / "attacks")
        one = filter_attacks(attacks, None, ["jb-001"])
        runner = RedTeamRunner(lenient_config, one)
        result = runner.run()[0]
        assert result.goal == "custom goal string for demo"
        assert "custom goal string for demo" in result.user_prompt

    def test_reports_render(self, lenient_config, tmp_path):
        lenient_config.run.output_dir = str(tmp_path)
        attacks = load_attacks(REPO / "attacks")
        runner = RedTeamRunner(lenient_config, attacks)
        results = runner.run()
        summary = compute_summary(results)

        md = render_markdown(lenient_config, summary, results)
        assert "Overall vulnerability score" in md
        assert "## Scorecard" in md
        assert "`pi-001`" in md or "pi-001" in md

        js = render_json(lenient_config, summary, results)
        payload = json.loads(js)
        assert payload["summary"]["n_run"] == len(results)
        assert len(payload["results"]) == len(results)