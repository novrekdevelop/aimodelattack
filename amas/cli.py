"""Command-line interface for AMAS."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from amas import __version__
from amas.config import AppConfig, load_config
from amas.db.loader import CATEGORY_LABELS, filter_attacks, load_attacks
from amas.errors import AmasError, AttackDataError, ConfigError, TargetError
from amas.report import render_json, render_markdown
from amas.runner import RedTeamRunner
from amas.scoring import compute_summary

try:  # rich console output when available
    from rich.console import Console
    from rich.table import Table

    _HAS_RICH = True
except Exception:  # pragma: no cover - very defensive
    _HAS_RICH = False


def _console():
    if _HAS_RICH:
        return Console()
    class _Plain:
        def print(self, *args, **kwargs):  # noqa: A003
            print(*args)
    return _Plain()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="amas",
        description="AI Model Attack Simulator - automated red-teaming of "
                    "LLM and agent endpoints.",
    )
    parser.add_argument(
        "--version", action="version", version=f"amas {__version__}"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def _add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--category",
            action="append",
            dest="categories",
            choices=sorted(CATEGORY_LABELS),
            help="limit to a category (repeatable)",
        )
        p.add_argument(
            "--attacks",
            default=None,
            help="comma-separated attack ids to include",
        )
        p.add_argument("--json", action="store_true", help="emit JSON to stdout")

    cmd_list = sub.add_parser(
        "list", help="list the attack catalogue",
        description="List the attack catalogue.",
    )
    _add_common(cmd_list)

    cmd_run = sub.add_parser(
        "run", help="run the attack battery against a target",
        description="Run the attack battery against a target.",
    )
    _add_common(cmd_run)
    cmd_run.add_argument(
        "--config", type=Path, default=None,
        help="JSON config file (default ./config.json)",
    )
    cmd_run.add_argument("--goal", default=None, help="override the injected goal text")
    cmd_run.add_argument("--iterations", type=int, default=None, help="run N batteries")
    cmd_run.add_argument("--concurrency", type=int, default=None, help="max parallel requests")
    cmd_run.add_argument("--output-dir", type=Path, default=None, help="report output dir")
    cmd_run.add_argument(
        "--formats", default=None, help="comma-separated report formats (md,json)"
    )
    cmd_run.add_argument("--quiet", action="store_true", help="no report files, console only")
    cmd_run.add_argument("--seed", type=int, default=None, help="randomization seed")
    return parser


def _resolve_config(args: argparse.Namespace) -> Path:
    path = args.config
    if path is not None:
        return path
    fallback = Path("config.json")
    if fallback.exists():
        return fallback
    if _HAS_RICH:
        _console().print(
            "[yellow]No --config given and ./config.json not found. "
            "Using defaults (mock target, full catalogue).[/yellow]"
        )
    return Path("config.json")  # does not exist -> defaults


def _apply_cli_overrides(config: AppConfig, args: argparse.Namespace) -> AppConfig:
    if getattr(args, "categories", None):
        config.run.categories = getattr(args, "categories", None)
    if getattr(args, "attacks", None):
        config.run.attack_ids = [
            i.strip() for i in args.attacks.split(",") if i.strip()
        ]
    if getattr(args, "goal", None):
        config.run.goal = args.goal
    if getattr(args, "iterations", None):
        config.run.iterations = args.iterations
    if getattr(args, "concurrency", None):
        config.run.max_concurrency = args.concurrency
    if getattr(args, "output_dir", None):
        config.run.output_dir = str(args.output_dir)
    if getattr(args, "formats", None):
        config.run.report_formats = [
            f.strip().lower() for f in args.formats.split(",") if f.strip()
        ]
    if getattr(args, "seed", None) is not None:
        config.run.seed = args.seed
    return config


def _cmd_list(args: argparse.Namespace, console) -> int:
    attacks = load_attacks()
    selected = filter_attacks(attacks, args.categories, None)
    if args.attacks:
        ids = [i.strip().lower() for i in args.attacks.split(",") if i.strip()]
        selected = [a for a in selected if a.id.lower() in ids]
    if args.json:
        import json as _json

        console.print(_json.dumps([a.to_dict() for a in selected], indent=2))
        return 0
    if not selected:
        console.print("[red]No attacks matched the filters.[/red]")
        return 1
    console.print(f"[bold]Catalogue: {len(selected)} attacks[/bold]")
    for attack in selected:
        sev = attack.severity
        color = "red" if sev == "high" else "yellow" if sev == "medium" else "green"
        console.print(
            f"  [cyan]{attack.id}[/cyan] {attack.category:16} "
            f"[{color}]{sev:6}[/] {attack.name}"
        )
        if attack.description:
            console.print(f"        {attack.description[:150]}")
    return 0


def _cmd_run(args: argparse.Namespace, console) -> int:
    cfg_path = _resolve_config(args)
    config = load_config(cfg_path)
    config = _apply_cli_overrides(config, args)

    attacks = load_attacks()
    selected = filter_attacks(attacks, config.run.categories, config.run.attack_ids)
    if not selected:
        console.print(
            "[red]No attacks selected. Check --category/--attacks against `amas list`.[/red]"
        )
        return 1

    judge_desc = (
        f"on ({config.judge.model})" if config.judge.enabled else "off"
    )
    console.print(
        f"[bold]AMAS[/bold] attacking [cyan]{config.target.name}[/cyan] "
        f"({config.target.model}) with [yellow]{len(selected)}[/yellow] attacks "
        f"(judge: {judge_desc})"
    )

    try:
        runner = RedTeamRunner(config, selected)
        results = runner.run()
    except (TargetError, ConfigError, AmasError) as exc:
        console.print(f"[red]Aborted:[/red] {exc}")
        return 2

    summary = compute_summary(results)

    if _HAS_RICH:
        score_color = "green" if summary.grade in ("A+", "A", "B") else (
            "yellow" if summary.grade == "C" else "red"
        )
        console.print()
        console.print(
            f"[bold]Overall vulnerability score:[/bold] "
            f"[{score_color}]{summary.score:.1f}/100 (grade {summary.grade})[/{score_color}]"
        )
        vt = Table(title="Result summary", show_header=True)
        vt.add_column("Verdict", style="bold")
        vt.add_column("Count")
        vt.add_row("Complied / partial", str(summary.n_complied))
        vt.add_row("Refused", str(summary.n_refused))
        vt.add_row("Ambiguous", str(summary.n_ambiguous))
        vt.add_row("Errors", str(summary.n_errors))
        console.print(vt)

        tbl = Table(title="Scorecard", show_header=True, header_style="bold magenta")
        for col in ("ID", "Attack", "Category", "Sev", "Verdict", "Score"):
            tbl.add_column(col)
        for r in results:
            style = "red" if r.final_verdict in ("complied", "partial") else None
            tbl.add_row(
                r.attack_id, r.attack_name[:30], r.category, r.severity,
                r.final_verdict, f"{r.final_score:.1f}", style=style,
            )
        console.print(tbl)
    else:
        console.print(
            f"Overall vulnerability score: {summary.score:.1f}/100 ({summary.grade})"
        )
        console.print(
            f"  complied={summary.n_complied} refused={summary.n_refused} "
            f"ambiguous={summary.n_ambiguous} errors={summary.n_errors}"
        )

    if not args.quiet:
        out_dir = Path(config.run.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        written: List[str] = []
        for fmt in config.run.report_formats:
            if fmt in ("markdown", "md"):
                path = out_dir / "report.md"
                path.write_text(
                    render_markdown(config, summary, results), encoding="utf-8"
                )
                written.append(str(path))
            elif fmt == "json":
                path = out_dir / "report.json"
                path.write_text(
                    render_json(config, summary, results), encoding="utf-8"
                )
                written.append(str(path))
        if written:
            console.print(f"\n[green]Reports written:[/green] {', '.join(written)}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    console = _console()
    try:
        if args.command == "list":
            return _cmd_list(args, console)
        if args.command == "run":
            return _cmd_run(args, console)
        parser.print_help()
        return 1
    except (AmasError, ConfigError, AttackDataError, TargetError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())