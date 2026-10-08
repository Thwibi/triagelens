"""Rule loading: parse, hash, route and compile health (spec 04 section 1)."""

from __future__ import annotations

from pathlib import Path

import pytest
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule

from app.config import Settings
from app.detect.routing import Route
from app.detect.rules import (
    KIND_BUILTIN,
    KIND_CUSTOM,
    KIND_SIGMA,
    RULE_TYPE_CORRELATION,
    RULE_TYPE_DETECTION,
    LoadedRule,
    LoadProblem,
    load_rules,
    load_rules_from,
)
from app.util.hashing import sha256_file

BACKEND_ROOT = Path(__file__).resolve().parents[1]
BUILTIN_DIR = BACKEND_ROOT / "rules" / "builtin"
MAP = BACKEND_ROOT / "rules" / "logsource_map.yaml"

#: The ten detection + six correlation documents of spec 04 section 10.
SPEC_IDS = {
    "7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e01",
    "7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e02",
    "7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e03",
    "7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e04",
    "7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e10",
    "7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e11",
    "7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e12",
    "7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e20",
    "7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e21",
    "7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e22",
    "7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e23",
    "7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e30",
    "7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e31",
    "7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e32",
    "7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e40",
    "7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e41",
}


def _write(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


def _load(tmp_path: Path) -> tuple[list[LoadedRule], list[LoadProblem]]:
    return load_rules(builtin_dir=tmp_path, logsource_map=MAP)


@pytest.fixture
def loaded() -> list[LoadedRule]:
    rules, problems = load_rules(builtin_dir=BUILTIN_DIR, logsource_map=MAP)
    assert problems == []
    return rules


DETECTION_DOC = (
    "title: Example Rule\n"
    "id: 11111111-2222-3333-4444-555555555555\n"
    "status: stable\n"
    "logsource: { category: webserver }\n"
    "detection:\n"
    "  selection:\n"
    "    cs-method: POST\n"
    "  condition: selection\n"
    "level: high\n"
    "tags: [attack.t1190]\n"
)


class TestBuiltinShipment:
    """The five files of spec 04 section 10, exactly as written."""

    def test_sixteen_documents_load_in_two_shapes(self, loaded: list[LoadedRule]) -> None:
        assert len(loaded) == 16
        detection = [r for r in loaded if r.rule_type == RULE_TYPE_DETECTION]
        correlation = [r for r in loaded if r.rule_type == RULE_TYPE_CORRELATION]
        assert len(detection) == 10
        assert len(correlation) == 6

    def test_every_rule_is_builtin(self, loaded: list[LoadedRule]) -> None:
        assert {r.kind for r in loaded} == {KIND_BUILTIN}

    def test_the_fixed_ids_from_the_spec_are_present(self, loaded: list[LoadedRule]) -> None:
        assert {r.id for r in loaded} == SPEC_IDS

    def test_every_builtin_rule_compiles_and_routes(self, loaded: list[LoadedRule]) -> None:
        for rule in loaded:
            assert rule.compile_error is None, rule.title
            assert not rule.unroutable, rule.title
            if rule.rule_type == RULE_TYPE_DETECTION:
                assert isinstance(rule.route, Route)
                assert rule.route.sql
            else:
                assert rule.route is None

    def test_detection_rules_carry_sigma_objects_and_logsources(
        self, loaded: list[LoadedRule]
    ) -> None:
        by_id = {r.id: r for r in loaded}
        ssh = by_id["7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e01"]
        assert isinstance(ssh.sigma_rule, SigmaRule)
        assert ssh.logsource == {"product": "linux", "service": "sshd"}
        web = by_id["7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e20"]
        assert web.logsource == {"category": "webserver"}

    def test_correlation_rules_have_no_logsource(self, loaded: list[LoadedRule]) -> None:
        by_id = {r.id: r for r in loaded}
        brute = by_id["7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e02"]
        assert isinstance(brute.sigma_rule, SigmaCorrelationRule)
        assert brute.logsource == {}

    @pytest.mark.parametrize(
        ("rule_id", "level", "status"),
        [
            ("7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e01", "informational", "stable"),
            ("7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e03", "critical", "stable"),
            ("7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e23", "medium", "test"),
            ("7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e40", "medium", "stable"),
        ],
    )
    def test_levels_and_statuses_read_as_plain_names(
        self, loaded: list[LoadedRule], rule_id: str, level: str, status: str
    ) -> None:
        rule = next(r for r in loaded if r.id == rule_id)
        assert rule.level == level
        assert rule.status == status

    def test_tags_are_in_rule_spelling(self, loaded: list[LoadedRule]) -> None:
        by_id = {r.id: r for r in loaded}
        assert "attack.t1110.001" in by_id["7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e01"].tags
        assert "attack.credential-access" in by_id["7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e01"].tags
        assert "attack.t1136.001" in by_id["7b1e9a52-3c0d-4f0e-9d51-0a1b2c3d4e40"].tags

    def test_the_hash_is_the_sha256_of_the_whole_file(self, loaded: list[LoadedRule]) -> None:
        firewall_hash = sha256_file(BUILTIN_DIR / "firewall.yml")
        from_firewall = [
            rule
            for rule in loaded
            if rule.file_path is not None and "firewall.yml" in rule.file_path
        ]
        assert len(from_firewall) == 3
        assert {r.sha256 for r in from_firewall} == {firewall_hash}

    def test_multi_document_paths_carry_the_document_index(self, loaded: list[LoadedRule]) -> None:
        ssh_paths: list[str] = []
        for rule in loaded:
            assert rule.file_path is not None
            assert "#" in rule.file_path
            if "linux_ssh_bruteforce" in rule.file_path:
                ssh_paths.append(rule.file_path)
        assert len(ssh_paths) == 4
        assert ssh_paths[0].endswith("linux_ssh_bruteforce.yml#1")
        assert ssh_paths[-1].endswith("linux_ssh_bruteforce.yml#4")

    def test_loading_twice_reproduces_everything(self, loaded: list[LoadedRule]) -> None:
        again, problems = load_rules(builtin_dir=BUILTIN_DIR, logsource_map=MAP)
        assert problems == []
        assert [(r.id, r.sha256, r.yaml, r.file_path) for r in again] == [
            (r.id, r.sha256, r.yaml, r.file_path) for r in loaded
        ]


class TestSettingsLoad:
    def test_load_rules_from_settings_finds_the_shipped_rules(self, settings: Settings) -> None:
        rules, problems = load_rules_from(settings)
        assert problems == []
        assert len(rules) == 16
        assert {r.kind for r in rules} == {KIND_BUILTIN}


class TestDocumentSplitting:
    def test_a_single_document_file_has_no_index(self, tmp_path: Path) -> None:
        _write(tmp_path, "single.yml", DETECTION_DOC)
        rules, problems = _load(tmp_path)
        assert problems == []
        assert len(rules) == 1
        assert rules[0].file_path is not None
        assert rules[0].file_path.endswith("single.yml")

    def test_documents_are_split_with_one_based_indexes(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "two.yml",
            DETECTION_DOC
            + "---\n"
            + DETECTION_DOC.replace("Example Rule", "Second Rule").replace(
                "11111111-2222-3333-4444-555555555555", "11111111-2222-3333-4444-666666666666"
            ),
        )
        rules, problems = _load(tmp_path)
        assert problems == []
        assert len(rules) == 2
        assert rules[0].file_path is not None
        assert rules[1].file_path is not None
        assert rules[0].file_path.endswith("two.yml#1")
        assert rules[1].file_path.endswith("two.yml#2")

    def test_a_non_mapping_document_is_a_problem_not_a_crash(self, tmp_path: Path) -> None:
        _write(tmp_path, "odd.yml", "just a string\n---\n" + DETECTION_DOC)
        rules, problems = _load(tmp_path)
        assert len(rules) == 1
        assert len(problems) == 1
        assert "not a mapping" in problems[0].error

    def test_invalid_yaml_fails_the_file_with_a_problem(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "broken.yml", "title: [unclosed\n  bad: :\n")
        rules, problems = _load(tmp_path)
        assert rules == []
        assert len(problems) == 1
        assert "invalid YAML" in problems[0].error
        assert problems[0].where == str(path)

    def test_an_empty_file_loads_nothing_and_nothing_fails(self, tmp_path: Path) -> None:
        _write(tmp_path, "empty.yml", "")
        _write(tmp_path, "comments.yml", "# just a comment\n")
        rules, problems = _load(tmp_path)
        assert (rules, problems) == ([], [])

    def test_filter_documents_are_skipped_silently(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "filtered.yml",
            DETECTION_DOC
            + "---\n"
            + "filter:\n"
            + "  name: exclude noise\n"
            + "  conditions:\n"
            + "    selection:\n"
            + "      cs-method: GET\n",
        )
        rules, problems = _load(tmp_path)
        assert problems == []
        assert len(rules) == 1

    def test_missing_directories_are_skipped(self, tmp_path: Path) -> None:
        rules, problems = load_rules(
            builtin_dir=tmp_path / "absent",
            sigma_dir=tmp_path / "also-absent",
            logsource_map=MAP,
        )
        assert (rules, problems) == ([], [])

    def test_sigma_and_custom_kinds_come_from_their_directories(self, tmp_path: Path) -> None:
        _write(tmp_path / "builtin", "b.yml", DETECTION_DOC)
        _write(tmp_path / "sigma" / "nested", "s.yml", DETECTION_DOC)
        _write(tmp_path / "custom", "c.yml", DETECTION_DOC)
        rules, problems = load_rules(
            builtin_dir=tmp_path / "builtin",
            sigma_dir=tmp_path / "sigma",
            custom_dir=tmp_path / "custom",
            logsource_map=MAP,
        )
        assert problems == []
        assert {r.kind for r in rules} == {KIND_BUILTIN, KIND_SIGMA, KIND_CUSTOM}


class TestParseAndCompileHealth:
    def test_a_rule_pysigma_rejects_becomes_health_not_a_crash(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "broken.yml",
            "title: Broken\nlogsource: { category: webserver }\ndetection: 5\nlevel: high\n",
        )
        rules, problems = _load(tmp_path)
        assert len(rules) == 1
        rule = rules[0]
        assert rule.sigma_rule is None
        assert rule.compile_error is not None
        assert "valid YAML map" in rule.compile_error
        assert rule.level == "high"  # the raw level survives the parse failure
        assert rule.title == "Broken"
        assert len(problems) == 1
        assert "cannot parse rule" in problems[0].error

    def test_an_invalid_raw_level_falls_back_to_informational(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "badlevel.yml",
            "title: Bad Level\nlogsource: { category: webserver }\ndetection: 5\nlevel: bananas\n",
        )
        rules, _ = _load(tmp_path)
        assert rules[0].level == "informational"

    def test_a_compile_failure_is_recorded_on_a_parsed_rule(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "noc.yml",
            "title: Undefined Selection\n"
            "logsource: { category: webserver }\n"
            "detection:\n"
            "  selection:\n"
            "    cs-method: POST\n"
            "  condition: missing\n"
            "level: high\n",
        )
        rules, problems = _load(tmp_path)
        assert problems == []  # parsed fine; only compilation failed
        rule = rules[0]
        assert isinstance(rule.sigma_rule, SigmaRule)
        assert rule.compile_error is not None
        assert "missing" in rule.compile_error
        assert not rule.unroutable

    def test_an_unknown_logsource_is_unroutable(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "plan9.yml",
            "title: From Space\n"
            "logsource: { product: plan9 }\n"
            "detection:\n"
            "  selection:\n"
            "    event_action: beep\n"
            "  condition: selection\n"
            "level: low\n",
        )
        rules, _ = _load(tmp_path)
        rule = rules[0]
        assert rule.unroutable
        assert rule.route is not None
        assert rule.route.unroutable
        assert rule.compile_error is None  # health classes stay independent

    def test_a_detection_without_logsource_never_matches_everything(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "nols.yml",
            "title: No Logsource\n"
            "detection:\n"
            "  selection:\n"
            "    cs-method: POST\n"
            "  condition: selection\n"
            "level: low\n",
        )
        rules, _ = _load(tmp_path)
        rule = rules[0]
        assert rule.unroutable  # parse failed *and* the route guard caught it

    def test_an_unknown_modifier_is_reported_as_rule_health(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "mod.yml",
            "title: Bad Modifier\n"
            "logsource: { category: webserver }\n"
            "detection:\n"
            "  selection:\n"
            "    cs-uri-query|nonexistent: x\n"
            "  condition: selection\n"
            "level: high\n",
        )
        rules, problems = _load(tmp_path)
        assert len(problems) == 1
        assert rules[0].compile_error is not None
        assert "nonexistent" in rules[0].compile_error

    def test_a_rule_without_an_id_gets_a_stable_generated_id(self, tmp_path: Path) -> None:
        body = DETECTION_DOC.replace("id: 11111111-2222-3333-4444-555555555555\n", "")
        _write(tmp_path, "noid.yml", body)
        first, _ = _load(tmp_path)
        second, _ = _load(tmp_path)
        assert first[0].id == second[0].id
        assert first[0].id  # non-empty

        changed = _load_after_change(tmp_path, body.replace("Example Rule", "Renamed"))
        assert changed[0].id != first[0].id

    def test_a_rule_without_a_level_defaults_to_informational(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "nolevel.yml",
            DETECTION_DOC.replace("level: high\n", ""),
        )
        rules, _ = _load(tmp_path)
        assert rules[0].level == "informational"
        assert rules[0].status == "stable"


def _load_after_change(tmp_path: Path, body: str) -> list[LoadedRule]:
    for existing in tmp_path.glob("*.yml"):
        existing.unlink()
    _write(tmp_path, "changed.yml", body)
    rules, _ = _load(tmp_path)
    return rules
