"""LLM-judge parsing tests (no network) + OpenAI-compatible adapter tests."""

from __future__ import annotations

import json

import pytest

from amas.config import JudgeConfig, TargetConfig
from amas.errors import TargetError
from amas.evaluator.judge import LLMJudge, _parse_judgment
from amas.targets.base import ChatMessage, OpenAICompatibleTarget


class TestParseJudgment:
    def test_plain_json(self):
        parsed = _parse_judgment(
            '{"verdict": "complied", "score": 9, "reason": "full output"}'
        )
        assert parsed["verdict"] == "complied"
        assert parsed["score"] == 9

    def test_fenced_json(self):
        parsed = _parse_judgment('```json\n{"verdict": "refused", "score": 1}\n```')
        assert parsed["verdict"] == "refused"

    def test_json_amid_prose(self):
        text = 'Based on my analysis: {"verdict": "partial", "score": 6.5, "reason": "almost"}. Hope this helps.'
        assert _parse_judgment(text)["verdict"] == "partial"

    def test_missing_json_raises(self):
        with pytest.raises(ValueError):
            _parse_judgment("no structure here at all")

    def test_judge_requires_base_url(self):
        cfg = JudgeConfig(enabled=True, base_url=None)
        with pytest.raises(TargetError):
            LLMJudge(cfg)


class _FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code
        self.text = json.dumps(payload)

    def json(self):
        return self._payload


class TestOpenAICompatibleTarget:
    def _target(self):
        cfg = TargetConfig(
            type="openai_compatible",
            base_url="https://api.test/v1",
            api_key="sk-x",
            model="m-1",
            max_tokens=64,
        )
        return OpenAICompatibleTarget(cfg)

    def test_url_building(self):
        t = self._target()
        assert t._url() == "https://api.test/v1/chat/completions"
        t2 = OpenAICompatibleTarget(
            TargetConfig(type="openai_compatible", base_url="https://x.test",
                         model="m"))
        assert t2._url() == "https://x.test/v1/chat/completions"
        t3 = OpenAICompatibleTarget(
            TargetConfig(type="openai_compatible",
                         base_url="https://x.test/v1/chat/completions",
                         model="m"))
        assert t3._url() == "https://x.test/v1/chat/completions"

    def test_chat_parses_content(self, monkeypatch):
        captured = {}

        def fake_post(url, json=None, headers=None, timeout=None):
            captured["url"] = url
            captured["payload"] = json
            captured["headers"] = headers
            return _FakeResponse(
                {"choices": [{"message": {"role": "assistant",
                                          "content": "Hello back"}}]}
            )

        monkeypatch.setattr("requests.post", fake_post)
        t = self._target()
        result = t.chat([ChatMessage(role="user", content="hi")], max_tokens=None)
        assert result.text == "Hello back"
        assert captured["url"].endswith("/chat/completions")
        assert captured["headers"]["Authorization"] == "Bearer sk-x"
        assert captured["payload"]["model"] == "m-1"
        assert captured["payload"]["max_tokens"] == 64

    def test_http_error_raises(self, monkeypatch):
        def fake_post(url, json=None, headers=None, timeout=None):
            return _FakeResponse({"error": "boom"}, status_code=400)

        monkeypatch.setattr("requests.post", fake_post)
        with pytest.raises(TargetError):
            self._target().chat([ChatMessage(role="user", content="hi")])

    def test_retries_on_429(self, monkeypatch):
        calls = {"n": 0}

        def fake_post(url, json=None, headers=None, timeout=None):
            calls["n"] += 1
            if calls["n"] < 3:
                return _FakeResponse({}, status_code=429)
            return _FakeResponse({"choices": [{"message": {"content": "ok"}}]})

        monkeypatch.setattr("requests.post", fake_post)
        t = self._target()  # max_retries defaults to 2 in TargetConfig
        result = t.chat([ChatMessage(role="user", content="hi")])
        assert calls["n"] == 3
        assert result.text == "ok"

    def test_no_base_url_raises(self):
        with pytest.raises(TargetError):
            OpenAICompatibleTarget(
                TargetConfig(type="openai_compatible", base_url="")
            )