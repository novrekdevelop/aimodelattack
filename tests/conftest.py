"""Shared fixtures: loads the real catalogue and configs."""

from __future__ import annotations

from pathlib import Path

import pytest

from amas.config import AppConfig, load_config
from amas.db.loader import load_attacks

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def attacks():
    return load_attacks(REPO / "attacks")


@pytest.fixture()
def lenient_config(tmp_path) -> AppConfig:
    cfg = load_config(REPO / "examples" / "mock_lenient.json")
    cfg.run.output_dir = str(tmp_path)
    return cfg


@pytest.fixture()
def strict_config(tmp_path) -> AppConfig:
    cfg = load_config(REPO / "examples" / "mock_strict.json")
    cfg.run.output_dir = str(tmp_path)
    return cfg