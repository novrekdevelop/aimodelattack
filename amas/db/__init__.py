"""Attack catalogue: `db` subpackage with YAML loader + validation."""

from amas.db.loader import (
    Attack,
    CATEGORY_LABELS,
    SEVERITY_LEVELS,
    load_attacks,
    resolve_attacks_dir,
)

__all__ = [
    "Attack",
    "CATEGORY_LABELS",
    "SEVERITY_LEVELS",
    "load_attacks",
    "resolve_attacks_dir",
]