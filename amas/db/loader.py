"""Load and validate the YAML attack catalogue.

The catalogue lives in the `attacks/` directory at the repository root (or an
override via the AMAS_ATTACKS_DIR environment variable). Every entry is a YAML
mapping with:

  id          unique identifier, e.g. "pi-001"
  name        human-readable technique name
  category    one of CATEGORY_LABELS
  severity    low | medium | high
  description 1-2 sentence explanation of the technique
  template    the prompt payload; placeholders {goal}, {goal_base64},
              {goal_hex}, {goal_leetspeak} are expanded at runtime
  refs        list of public references
  system      optional replacement system prompt (attacks that swap rules)
  history     optional list of {"role","content"} to set up a conversation
  requires_goal  whether the attack needs the configured goal(s)
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import yaml

from amas.config import CATEGORIES
from amas.errors import AttackDataError

SEVERITY_LEVELS = ("low", "medium", "high")
CATEGORY_LABELS = dict(CATEGORIES)


@dataclass
class Attack:
    id: str
    name: str
    category: str
    severity: str
    description: str
    template: str
    refs: List[str] = field(default_factory=list)
    system: Optional[str] = None
    history: List[Dict[str, str]] = field(default_factory=list)
    requires_goal: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
            "description": self.description,
            "template": self.template,
            "refs": list(self.refs),
            "system": self.system,
            "history": list(self.history),
            "requires_goal": self.requires_goal,
        }


def resolve_attacks_dir() -> Path:
    """Locate the attacks/ directory (repo root by default)."""
    override = os.environ.get("AMAS_ATTACKS_DIR")
    if override:
        path = Path(override)
        if path.is_dir():
            return path
        raise AttackDataError(f"AMAS_ATTACKS_DIR is not a directory: {override}")
    here = Path(__file__).resolve()
    # amas/db/loader.py -> repo root (two parents up).
    repo_root = here.parents[2]
    candidates = [
        repo_root / "attacks",
        here.parents[0] / ".." / ".." / "attacks",
    ]
    for cand in candidates:
        cand = cand.resolve()
        if cand.is_dir():
            return cand
    raise AttackDataError(
        f"could not locate attacks/ directory (tried {[str(c) for c in candidates]})"
    )


def _validate(entry: Dict[str, Any], source: Path, index: int) -> None:
    errs: List[str] = []
    for key in ("id", "name", "category", "severity", "template"):
        if not entry.get(key):
            errs.append(f"missing or empty '{key}'")
    if entry.get("category") not in CATEGORY_LABELS:
        errs.append(
            f"category {entry.get('category')!r} not in {sorted(CATEGORY_LABELS)}"
        )
    if entry.get("severity") not in SEVERITY_LEVELS:
        errs.append(f"severity {entry.get('severity')!r} not in {SEVERITY_LEVELS}")
    if errs:
        raise AttackDataError(
            f"invalid attack entry #{index} in {source.name}: {errs}"
        )


def _parse_one(entry: Dict[str, Any], source: Path, index: int) -> Attack:
    if not isinstance(entry, dict):
        raise AttackDataError(
            f"attack entry #{index} in {source.name} must be a mapping"
        )
    _validate(entry, source, index)
    history_raw = entry.get("history") or []
    if not isinstance(history_raw, list):
        raise AttackDataError(
            f"attack {entry.get('id')!r} in {source.name}: 'history' must be a list"
        )
    history: List[Dict[str, str]] = []
    for turn in history_raw:
        role = str(turn.get("role", ""))
        content = str(turn.get("content", ""))
        if role not in ("user", "assistant") or not content:
            raise AttackDataError(
                f"attack {entry.get('id')!r} in {source.name}: bad history turn {turn}"
            )
        history.append({"role": role, "content": content})
    refs_raw = entry.get("refs") or []
    refs = [str(r) for r in refs_raw] if isinstance(refs_raw, list) else []
    return Attack(
        id=str(entry["id"]),
        name=str(entry["name"]),
        category=str(entry["category"]),
        severity=str(entry["severity"]),
        description=str(entry.get("description", "")),
        template=str(entry["template"]),
        refs=refs,
        system=entry.get("system"),
        history=history,
        # Extraction attacks always target the system prompt itself; they do
        # not need a concrete injected goal by default.
        requires_goal=bool(
            entry.get("requires_goal", entry.get("category") != "system_extraction")
        ),
    )


def load_attacks(dir_path: Optional[Path] = None) -> List[Attack]:
    """Load the full catalogue from YAML files in *dir_path* (or default)."""
    directory = dir_path or resolve_attacks_dir()
    files = sorted(directory.glob("*.yaml")) + sorted(directory.glob("*.yml"))
    if not files:
        raise AttackDataError(f"no *.yaml attack files found in {directory}")

    attacks: List[Attack] = []
    seen: Dict[str, str] = {}
    for path in files:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        if loaded is None:
            continue
        entries = loaded if isinstance(loaded, list) else loaded.get("attacks", [])
        if not isinstance(entries, list):
            raise AttackDataError(
                f"{path.name}: top level must be a list of attacks "
                f"(or an object with an 'attacks' list)"
            )
        for i, entry in enumerate(entries):
            if entry is None:
                continue
            attack = _parse_one(entry, path, i)
            if attack.id in seen:
                raise AttackDataError(
                    f"duplicate attack id {attack.id!r} in {path.name} "
                    f"(already defined in {seen[attack.id]})"
                )
            seen[attack.id] = path.name
            attacks.append(attack)
    return attacks


def filter_attacks(
    attacks: Sequence[Attack],
    categories: Optional[List[str]] = None,
    attack_ids: Optional[List[str]] = None,
) -> List[Attack]:
    """Apply category / id filters in a stable order."""
    result = list(attacks)
    if categories:
        wanted = [c.lower() for c in categories]
        result = [a for a in result if a.category in wanted]
    if attack_ids:
        ids = {i.lower() for i in attack_ids}
        result = [a for a in result if a.id.lower() in ids]
    return result