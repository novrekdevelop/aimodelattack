"""Catalogue loading tests."""

from __future__ import annotations

import yaml

from amas.config import CATEGORIES
from amas.db.loader import SEVERITY_LEVELS, Attack, filter_attacks


class TestCatalogue:
    def test_size_and_categories(self, attacks):
        assert len(attacks) >= 40, f"expected >= 40 attacks, got {len(attacks)}"
        cats = {}
        for a in attacks:
            cats[a.category] = cats.get(a.category, 0) + 1
        assert cats.get("prompt_injection", 0) >= 10
        assert cats.get("jailbreak", 0) >= 15
        assert cats.get("system_extraction", 0) >= 8

    def test_ids_unique(self, attacks):
        ids = [a.id for a in attacks]
        assert len(ids) == len(set(ids))

    def test_fields_valid(self, attacks):
        for a in attacks:
            assert a.id, "id required"
            assert a.name, "name required"
            assert a.category in CATEGORIES
            assert a.severity in SEVERITY_LEVELS
            content = a.template + " " + " ".join(t["content"] for t in a.history)
            placeholders = ("{goal}", "{goal_base64}", "{goal_hex}", "{goal_leetspeak}")
            assert any(p in content for p in placeholders) or not a.requires_goal
            assert isinstance(a.refs, list)
            for turn in a.history:
                assert turn["role"] in ("user", "assistant")
                assert turn["content"]

    def test_to_dict_roundtrip(self, attacks):
        for a in attacks[:5]:
            d = a.to_dict()
            assert d["id"] == a.id
            assert set(d) == {
                "id", "name", "category", "severity", "description",
                "template", "refs", "system", "history", "requires_goal",
            }

    def test_filter_by_category(self, attacks):
        only = filter_attacks(attacks, categories=["jailbreak"])
        assert only and all(a.category == "jailbreak" for a in only)

    def test_filter_by_ids(self, attacks):
        only = filter_attacks(attacks, attack_ids=["pi-001", "jb-013"])
        assert {a.id for a in only} == {"pi-001", "jb-013"}

    def test_filter_unknown_ids_yields_empty(self, attacks):
        assert filter_attacks(attacks, attack_ids=["nope-99"]) == []

    def test_many_shot_history_present(self, attacks):
        jb13 = next(a for a in attacks if a.id == "jb-013")
        assert len(jb13.history) == 7
        assert "{goal}" in jb13.history[-1]["content"]

    def test_yaml_files_parse(self, attacks):
        import yaml as _yaml

        from amas.db.loader import resolve_attacks_dir

        for path in sorted(resolve_attacks_dir().glob("*.yaml")):
            data = _yaml.safe_load(path.read_text(encoding="utf-8"))
            assert isinstance(data, list), f"{path.name} must be a list"
            assert data