"""Vendored SigmaHQ sample and compile health (spec 04 section 11, spec 09 D-12).

The shipped ``rules/sigma`` tree is a deterministic sample from a pinned
SigmaHQ/sigma commit (see ``SOURCE.txt`` next to it). These tests hold the tree
to the acceptance bar a fresh sync must meet: at least 200 rules that parse,
compile with the SQLite backend and route through the shipped logsource map,
a clean, reproducible load, and provenance that survives a rerun.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest

from app.detect.rules import KIND_SIGMA, RULE_TYPE_DETECTION, LoadedRule, load_rules

BACKEND_ROOT = Path(__file__).resolve().parents[1]
SIGMA_DIR = BACKEND_ROOT / "rules" / "sigma"
MAP = BACKEND_ROOT / "rules" / "logsource_map.yaml"

#: The acceptance floor of spec 04 section 11 and spec 09 D-12.
MIN_RULES = 200

_LEVELS = frozenset({"informational", "low", "medium", "high", "critical"})
_CATEGORIES = ("windows", "linux", "web", "network")


@pytest.fixture(scope="module")
def loaded() -> list[LoadedRule]:
    """Every rule in the vendored tree, exactly once."""
    rules, problems = load_rules(sigma_dir=SIGMA_DIR, logsource_map=MAP)
    assert problems == []
    return rules


class TestVendoredSample:
    def test_at_least_200_rules_compile_and_route(self, loaded: list[LoadedRule]) -> None:
        assert len(loaded) >= MIN_RULES
        for rule in loaded:
            assert rule.compile_error is None, rule.title
            assert not rule.unroutable, rule.title
            assert rule.rule_type == RULE_TYPE_DETECTION, rule.title

    def test_every_rule_is_sigma_kind(self, loaded: list[LoadedRule]) -> None:
        assert {rule.kind for rule in loaded} == {KIND_SIGMA}

    def test_loads_without_problems(self) -> None:
        rules, problems = load_rules(sigma_dir=SIGMA_DIR, logsource_map=MAP)
        assert problems == []
        assert rules

    def test_levels_are_plain_known_names(self, loaded: list[LoadedRule]) -> None:
        assert {rule.level for rule in loaded} <= _LEVELS

    def test_the_load_is_deterministic(self, loaded: list[LoadedRule]) -> None:
        again, problems = load_rules(sigma_dir=SIGMA_DIR, logsource_map=MAP)
        assert problems == []
        assert [(rule.id, rule.sha256, rule.yaml, rule.file_path) for rule in again] == [
            (rule.id, rule.sha256, rule.yaml, rule.file_path) for rule in loaded
        ]

    def test_windows_linux_web_and_network_are_all_represented(
        self, loaded: list[LoadedRule]
    ) -> None:
        seen = {_category(rule) for rule in loaded}
        assert set(_CATEGORIES) <= seen

    def test_the_windows_sample_spans_families(self, loaded: list[LoadedRule]) -> None:
        families = {
            part for rule in loaded if _category(rule) == "windows" for part in _parts(rule)
        }
        assert len(families) >= 5


class TestProvenance:
    def test_the_drl_license_text_is_vendored(self) -> None:
        text = (SIGMA_DIR / "LICENSE").read_text(encoding="utf-8")
        assert "Detection Rule License (DRL) 1.1" in text
        assert "THE RULES ARE PROVIDED" in text

    def test_source_txt_records_the_pinned_commit(self) -> None:
        text = (SIGMA_DIR / "SOURCE.txt").read_text(encoding="utf-8")
        assert "Pinned commit: 48f2d096991a9ae89fd2710804901d1cd88d9746" in text
        assert "SPDX: DRL-1.1" in text
        assert re.search(r"^Selected: \d+ rule document", text, re.M)

    def test_source_txt_sha_matches_the_vendored_tree(self) -> None:
        text = (SIGMA_DIR / "SOURCE.txt").read_text(encoding="utf-8")
        recorded = _line_after(text, "Tree SHA-256")
        assert recorded == _tree_sha256()


def _category(rule: LoadedRule) -> str:
    parts = (rule.file_path or "").split("#")[0].replace("\\", "/").split("/")
    for part in parts:
        if part in _CATEGORIES:
            return part
    return "?"


def _parts(rule: LoadedRule) -> list[str]:
    parts = (rule.file_path or "").split("#")[0].replace("\\", "/").split("/")
    try:
        index = parts.index("windows")
    except ValueError:
        return []
    return [part for part in parts[index + 1 :] if part and part != ".yml"]


def _line_after(text: str, key: str) -> str:
    for line in text.splitlines():
        if line.startswith(key + ":"):
            return line.split(":", 1)[1].strip()
    raise AssertionError(f"no {key!r} line in SOURCE.txt")


def _tree_sha256() -> str:
    """Reproduce ``scripts/update_rules.py``'s tree digest."""
    per_category: dict[str, list[tuple[str, str]]] = {name: [] for name in _CATEGORIES}
    for path in SIGMA_DIR.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in {".yml", ".yaml"}:
            continue
        rel = path.relative_to(SIGMA_DIR).as_posix()
        category = rel.split("/", 1)[0]
        per_category.setdefault(category, []).append(
            (rel, hashlib.sha256(path.read_bytes()).hexdigest())
        )
    entries: list[str] = []
    for category in _CATEGORIES:
        for rel, digest in sorted(per_category.get(category, [])):
            entries.append(f"{rel} {digest}")
    return hashlib.sha256("\n".join(entries).encode("utf-8")).hexdigest()
