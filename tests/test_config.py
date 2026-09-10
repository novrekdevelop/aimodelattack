"""Config loading tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from amas.config import DEFAULT_GOALS, load_config
from amas.errors import ConfigError

REPO = Path(__file__).resolve().parents[1]


class TestLoadConfig:
    def test_missing_file(self):
        with pytest.raises(ConfigError):
            load_config(REPO / "does-not-exist.json")

    def test_invalid_json(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{ not json", encoding="utf-8")
        with pytest.raises(ConfigError):
            load_config(bad)

    def test_defaults_when_no_file(self):
        cfg = load_config(None)
        assert cfg.target.type == "openai_compatible"
        assert cfg.run.iterations == 1
        assert cfg.run.report_formats == ["markdown", "json"]
        assert cfg.run.goals == DEFAULT_GOALS

    def test_example_parses(self):
        cfg = load_config(REPO / "config.example.json")
        assert cfg.target.type == "openai_compatible"
        assert cfg.target.base_url.startswith("https://")
        assert cfg.judge.enabled is True
        assert len(cfg.run.goals) >= 3

    def test_env_overrides(self, monkeypatch, tmp_path):
        cfg = load_config(None)
        monkeypatch.setenv("AMAS_TARGET_URL", "http://127.0.0.1:9000/v1")
        monkeypatch.setenv("AMAS_API_KEY", "sk-secret")
        monkeypatch.setenv("AMAS_JUDGE_URL", "http://127.0.0.1:9001/v1")
        cfg2 = load_config(None)
        assert cfg2.target.base_url == "http://127.0.0.1:9000/v1"
        assert cfg2.target.api_key == "sk-secret"
        assert cfg2.judge.enabled is True

    def test_mock_config(self):
        cfg = load_config(REPO / "examples" / "mock_lenient.json")
        assert cfg.target.type == "mock"
        assert cfg.target.mock_mode == "lenient"
        assert cfg.judge.enabled is False

    def test_invalid_target_type(self, tmp_path):
        bad = tmp_path / "cfg.json"
        bad.write_text(json.dumps({"target": {"type": "wat"}}), encoding="utf-8")
        with pytest.raises(ConfigError):
            load_config(bad)