"""Report generation: Markdown + JSON.

The Markdown report is the primary human artifact: executive summary,
scorecard, category breakdown and detailed findings with prompt/response
excerpts. JSON is the machine-readable sibling.
"""

from __future__ import annotations

import datetime as _dt
import json
from typing import List, Sequence

from amas.config import CATEGORIES, AppConfig
from amas.runner import AttackResult
from amas.scoring import Summary

SEVERITY_GLYPH = {"high": "🟥", "medium": "🟧", "low": "🟨"}
VERDICT_GLYPH = {
    "complied": "✅",
    "partial": "⚠️",
    "ambiguous": "❓",
    "refused": "🛡️",
    "error": "💥",
}


def _truncate(text: str, limit: int = 500) -> str:
    if not text:
        return "(no response)"
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _grade_color(grade: str) -> str:
    if grade in ("A+", "A", "B"):
        return "🟢"
    if grade in ("C",):
        return "🟠"
    return "🔴"


def _scorecard(config: AppConfig, results: Sequence[AttackResult]) -> List[str]:
    lines: List[str] = []
    lines.append("## Scorecard")
    lines.append("")
    lines.append("| ID | Attack | Category | Severity | Verdict | Score |")
    lines.append("|---|---|---|---|---|---|")
    for r in results:
        glyph = VERDICT_GLYPH.get(r.final_verdict, "❓")
        lines.append(
            f"| `{r.attack_id}` | {r.attack_name} | {r.category} | "
            f"{r.severity} | {glyph} {r.final_verdict} | {r.final_score:.1f}/10 |"
        )
    lines.append("")
    return lines


def _detailed_findings(results: Sequence[AttackResult]) -> List[str]:
    lines: List[str] = []
    lines.append("## Detailed findings")
    lines.append("")
    hits = [r for r in results if r.final_verdict in ("complied", "partial")]
    if not hits:
        lines.append(
            "_No attacks succeeded. The endpoint held against this battery._ 🛡️"
        )
    for r in hits:
        lines.append(
            f"### {SEVERITY_GLYPH.get(r.severity, '🟨')} [{r.severity.upper()}] "
            f"`{r.attack_id}` — {r.attack_name}"
        )
        lines.append("")
        lines.append(f"**Goal:** {r.goal}")
        lines.append("")
        lines.append("**Request sent:**")
        lines.append("")
        lines.append(f"> {_truncate(r.user_prompt, 600)}")
        lines.append("")
        lines.append(
            f"**Model response:** (score {r.final_score:.1f}/10, "
            f"verdict *{r.final_verdict}*)"
        )
        lines.append("")
        lines.append(f"> {_truncate(r.response, 700)}")
        lines.append("")
        if r.rule and r.rule.evidence:
            lines.append("**Rule evidence:**")
            for item in r.rule.evidence:
                lines.append(f"- {item}")
            lines.append("")
        if r.judge:
            lines.append(
                f"**Judge:** *{r.judge.verdict}* — "
                f"score {r.judge.score:.1f}/10 — {r.judge.reason}"
            )
            lines.append("")
    return lines


def render_markdown(
    config: AppConfig,
    summary: Summary,
    results: Sequence[AttackResult],
) -> str:
    lines: List[str] = []
    lines.append("# ⚔️ AMAS Red-Team Report")
    lines.append("")
    lines.append(f"**Target:** {config.target.name} ({config.target.model})")
    lines.append(f"**Endpoint:** {config.target.base_url or 'mock://local'}")
    lines.append(
        f"**Generated:** {_dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )
    judge_desc = (
        f"enabled ({config.judge.model})" if config.judge.enabled else "rules-only"
    )
    lines.append(f"**Judge:** {judge_desc}")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(
        f"{_grade_color(summary.grade)} **Overall vulnerability score: "
        f"{summary.score:.1f}/100** (grade **{summary.grade}**) — "
        f"higher means more exposed."
    )
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---|")
    lines.append(f"| Attacks executed | {summary.n_run} |")
    lines.append(f"| Confirmed vulnerabilities | {summary.n_complied} |")
    lines.append(f"| Refused / defended | {summary.n_refused} |")
    lines.append(f"| Ambiguous (judge recommended) | {summary.n_ambiguous} |")
    lines.append(f"| Errors | {summary.n_errors} |")
    lines.append("")

    if summary.top_findings:
        lines.append("### Top findings")
        for i, finding in enumerate(summary.top_findings, start=1):
            glyph = SEVERITY_GLYPH.get(str(finding.get("severity")), "🟨")
            lines.append(
                f"{i}. {glyph} `{finding['attack_id']}` {finding['name']} "
                f"— {finding['verdict']} (score {finding['score']:.1f}/10)"
            )
        lines.append("")

    lines.append("## Category breakdown")
    lines.append("")
    lines.append("| Category | Run | Compiled | Refused | Ambiguous | Errors |")
    lines.append("|---|---|---|---|---|---|")
    for cat, data in sorted(summary.category_breakdown.items()):
        label = CATEGORIES.get(cat, cat)
        lines.append(
            f"| {label} | {data['n']} | {data['complied']} | {data['refused']} "
            f"| {data['ambiguous']} | {data['errors']} |"
        )
    lines.append("")

    lines += _scorecard(config, results)
    lines += _detailed_findings(results)

    lines.append("---")
    lines.append("")
    lines.append("## Methodology")
    lines.append("")
    lines.append(
        "This battery drove a catalogue of 40+ publicly-documented prompt-injection, "
        "jailbreak and system-extraction techniques against the target endpoint. Each "
        "response was first classified by a rule engine (refusal phrasing and "
        "system-prompt leakage heuristics). Where the judge was enabled, it refined "
        "borderline verdicts. The vulnerability score is the severity-weighted mean "
        "of per-attack scores (0–10) mapped to 0–100."
    )
    lines.append("")
    lines.append(
        "_Generated by AMAS (AI Model Attack Simulator). For authorized security "
        "testing only._"
    )
    lines.append("")
    return "\n".join(lines)


def render_json(
    config: AppConfig,
    summary: Summary,
    results: Sequence[AttackResult],
) -> str:
    payload = {
        "tool": "amas",
        "target": {
            "name": config.target.name,
            "type": config.target.type,
            "endpoint": config.target.base_url,
            "model": config.target.model,
        },
        "judge": {
            "enabled": config.judge.enabled,
            "model": config.judge.model,
        },
        "summary": summary.to_dict(),
        "results": [r.to_dict() for r in results],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)
    lines.append("")