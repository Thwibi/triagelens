"""MITRE ATT&CK enrichment (spec 04 section 7, spec 09 D-10).

Boundary coverage for tag parsing (technique, sub-technique, tactic with
underscores, group, unknown ID), parent credit through sub-techniques,
the shipped fallback map, matrix aggregation and Navigator layer schema
validation against the vendored layer 4.5 schema.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from app.db.connection import Database, atomic
from app.mitre import (
    AttackBundleError,
    MitreCatalogue,
    build_layer,
    enrich_run_alerts,
    load_alert_mappings,
    load_bundle,
    load_fallbacks,
    matrix_for_case,
    parse_sigma_tags,
    resolve_alert_mitre,
    resolve_rule_tags,
)
from app.mitre.fallbacks import match_fallback
from app.models.rule import KIND_BUILTIN, RULE_TYPE_DETECTION, RuleRecord

BACKEND_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_BUNDLE = BACKEND_ROOT / "tests" / "fixtures" / "enterprise-attack-mini.json"
FALLBACKS_YAML = BACKEND_ROOT / "data" / "mitre_fallbacks.yaml"
LAYER_SCHEMA = BACKEND_ROOT / "tests" / "fixtures" / "navigator_layer.schema.json"

_ISO = "2026-01-01T00:00:00.000Z"
_TS = 1_700_000_000_000


def _seed_case(database: Database) -> None:
    database.writer.execute(
        "INSERT INTO cases (id, name, description, default_timezone, created_at, updated_at) "
        "VALUES ('case-1', 'case-1', NULL, 'UTC', ?, ?)",
        (_ISO, _ISO),
    )
    database.writer.execute(
        "INSERT OR IGNORE INTO detection_runs (id, case_id, profile, tool_version, "
        "ruleset_hash, attack_version, started_at, finished_at, status) "
        "VALUES ('run-1', 'case-1', 'standard', '1', ?, '', ?, NULL, 'done')",
        ("0" * 64, _ISO),
    )


def _catalogue(database: Database) -> MitreCatalogue:
    load_bundle(database.writer, FIXTURE_BUNDLE)
    return MitreCatalogue.load(database.writer)


def _rule_with_tags(rule_id: str, tags: tuple[str, ...]) -> RuleRecord:
    return RuleRecord(
        id=rule_id,
        title=f"Rule {rule_id}",
        kind=KIND_BUILTIN,
        rule_type=RULE_TYPE_DETECTION,
        level="high",
        status="stable",
        enabled=True,
        yaml="title: x\nlogsource:\n  product: linux\n  service: sshd\n",
        tags=tags,
        logsource={"product": "linux", "service": "sshd"},
        file_path=None,
        sha256="deadbeef",
        compile_error=None,
        unroutable=False,
        updated_at=_ISO,
    )


def _insert_alert(
    database: Database,
    alert_id: str,
    *,
    level: str = "high",
    tactics: tuple[str, ...] = (),
    technique_ids: tuple[str, ...] = (),
    rule_title: str = "SSH Brute Force",
    rule_id: str = "rule-1",
) -> None:
    with atomic(database.writer):
        database.writer.execute(
            "INSERT INTO alerts ("
            "id, case_id, run_id, rule_id, rule_title, rule_kind, rule_type, "
            "level, score, status, group_key, first_seen_ms, last_seen_ms, "
            "match_count, created_at, tactics_json, techniques_json, "
            "groups_software_json"
            ") VALUES (?, 'case-1', 'run-1', ?, ?, 'builtin', 'detection', "
            "?, 0, 'new', '', 0, 0, 0, ?, ?, ?, '[]')",
            (
                alert_id,
                rule_id,
                rule_title,
                level,
                _ISO,
                json.dumps(list(tactics)),
                json.dumps([{"id": tid, "name": tid, "source": "tag"} for tid in technique_ids]),
            ),
        )


def _insert_event(
    database: Database,
    event_id: int,
    *,
    channel: str | None = "Security",
    sigma_event_id: int | None = 1102,
    event_action: str | None = None,
) -> None:
    database.writer.execute(
        "INSERT INTO events (case_id, source_id, record_ref, ts_ms, ts_iso, log_type, "
        "ls_category, host, channel, app_name, user_name, message, raw, event_action, "
        "src_ip, fields_json, event_id) VALUES ('case-1', 'src-1', ?, ?, NULL, "
        "'windows_evtx', '', NULL, ?, '', NULL, '', '{}', ?, NULL, '{}', ?)",
        (str(event_id), _TS, channel, event_action, sigma_event_id),
    )


def _link_alert_event(database: Database, alert_id: str, event_row_id: int) -> None:
    database.writer.execute(
        "INSERT INTO alert_events (alert_id, event_id) VALUES (?, ?)",
        (alert_id, event_row_id),
    )


# --------------------------------------------------------------------------
# Tag parsing
# --------------------------------------------------------------------------


class TestTagParsing:
    def test_technique_and_subtechnique_ids_are_uppercased(self) -> None:
        parsed = parse_sigma_tags(["attack.t1059", "attack.t1059.001"])
        assert parsed.technique_ids == ("T1059", "T1059.001")

    def test_tactic_underscores_become_hyphens(self) -> None:
        parsed = parse_sigma_tags(["attack.defense_evasion", "attack.credential_access"])
        assert parsed.tactic_names == ("defense-evasion", "credential-access")

    def test_group_and_software_ids(self) -> None:
        parsed = parse_sigma_tags(["attack.g0032", "attack.s0002"])
        assert parsed.group_ids == ("G0032",)
        assert parsed.software_ids == ("S0002",)

    def test_non_attack_tags_are_ignored(self) -> None:
        parsed = parse_sigma_tags(["car", "tlp:amber", "attack."])
        assert parsed == parse_sigma_tags([])

    def test_unparseable_attack_tag_lands_in_other(self) -> None:
        parsed = parse_sigma_tags(["attack.x!nv@lid"])
        assert parsed.other == ("attack.x!nv@lid",)

    def test_duplicate_tags_collapse(self) -> None:
        parsed = parse_sigma_tags(["attack.t1059", "attack.T1059", "attack.t1059"])
        assert parsed.technique_ids == ("T1059",)


# --------------------------------------------------------------------------
# STIX loading
# --------------------------------------------------------------------------


class TestLoader:
    def test_bundle_version_comes_from_the_bundle(self, database: Database) -> None:
        version = load_bundle(database.writer, FIXTURE_BUNDLE)
        assert version == "16.1.0"

    def test_explicit_version_override_wins(self, database: Database) -> None:
        version = load_bundle(database.writer, FIXTURE_BUNDLE, attack_version="17.1.0")
        assert version == "17.1.0"

    def test_version_falls_back_to_newest_modified_date(self, database: Database) -> None:
        bundle = {
            "type": "bundle",
            "id": "bundle--x",
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--a",
                    "name": "A",
                    "modified": "2024-03-01T00:00:00.000Z",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T1000"}
                    ],
                },
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--b",
                    "name": "B",
                    "modified": "2024-10-04T00:00:00.000Z",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T1001"}
                    ],
                },
            ],
        }
        assert load_bundle(database.writer, bundle) == "2024-10-04"

    def test_tactics_load_in_canonical_order(self, database: Database) -> None:
        load_bundle(database.writer, FIXTURE_BUNDLE)
        rows = database.writer.execute(
            "SELECT shortname, order_idx FROM mitre_tactics ORDER BY order_idx"
        ).fetchall()
        assert [row["shortname"] for row in rows] == [
            "execution",
            "persistence",
            "credential-access",
        ]
        assert [row["order_idx"] for row in rows] == [3, 4, 7]

    def test_subtechnique_parent_is_credited_from_the_relationship(
        self, database: Database
    ) -> None:
        catalogue = _catalogue(database)
        sub = catalogue.techniques["T1059.001"]
        assert sub.is_subtechnique is True
        assert sub.parent_id == "T1059"
        assert catalogue.techniques["T1059"].is_subtechnique is False

    def test_deprecated_and_revoked_patterns_stay_flagged(self, database: Database) -> None:
        catalogue = _catalogue(database)
        assert catalogue.techniques["T9998"].name == "Deprecated Pattern"
        assert catalogue.techniques["T9997"].name == "Revoked Pattern"

    def test_groups_and_software_load(self, database: Database) -> None:
        catalogue = _catalogue(database)
        assert catalogue.groups_software["G0032"].kind == "group"
        assert catalogue.groups_software["S0002"].kind == "software"

    def test_meta_records_version_time_and_hash(self, database: Database) -> None:
        load_bundle(database.writer, FIXTURE_BUNDLE)
        meta = {
            str(row["key"]): str(row["value"])
            for row in database.writer.execute("SELECT key, value FROM mitre_meta")
        }
        assert meta["attack_version"] == "16.1.0"
        assert re.fullmatch(r"[0-9a-f]{64}", meta["sha256"])
        assert meta["loaded_at"]

    def test_reloading_replaces_instead_of_duplicating(self, database: Database) -> None:
        load_bundle(database.writer, FIXTURE_BUNDLE)
        load_bundle(database.writer, FIXTURE_BUNDLE)
        count = database.writer.execute("SELECT COUNT(*) FROM mitre_techniques").fetchone()
        assert count is not None
        assert int(count[0]) == 8

    def test_a_non_bundle_document_is_rejected(self, database: Database) -> None:
        with pytest.raises(AttackBundleError, match="not a STIX bundle"):
            load_bundle(database.writer, {"type": "collection", "objects": []})

    def test_invalid_json_is_rejected(self, database: Database, tmp_path: Path) -> None:
        broken = tmp_path / "broken.json"
        broken.write_text("{not json", encoding="utf-8")
        with pytest.raises(AttackBundleError, match="not valid JSON"):
            load_bundle(database.writer, broken)


# --------------------------------------------------------------------------
# Tag resolution
# --------------------------------------------------------------------------


class TestResolution:
    def test_known_ids_resolve_with_names(self, database: Database) -> None:
        resolved = resolve_rule_tags(["attack.t1110.001"], _catalogue(database))
        assert [technique.name for technique in resolved.techniques] == ["Password Guessing"]
        assert resolved.unresolved_tags == ()

    def test_unknown_id_stays_an_unresolved_raw_tag(self, database: Database) -> None:
        resolved = resolve_rule_tags(["attack.t9999"], _catalogue(database))
        assert resolved.techniques == ()
        assert resolved.unresolved_tags == ("attack.t9999",)

    def test_unknown_tactic_and_group_are_unresolved(self, database: Database) -> None:
        resolved = resolve_rule_tags(
            ["attack.time_traveling", "attack.g9999"], _catalogue(database)
        )
        assert resolved.tactics == ()
        assert resolved.groups_software == ()
        assert "attack.time_traveling" in resolved.unresolved_tags
        assert "attack.g9999" in resolved.unresolved_tags

    def test_known_tactic_tag_resolves(self, database: Database) -> None:
        resolved = resolve_rule_tags(["attack.credential_access"], _catalogue(database))
        assert resolved.tactics == ("credential-access",)


# --------------------------------------------------------------------------
# Fallbacks
# --------------------------------------------------------------------------


class TestFallbacks:
    def test_shipped_fallback_file_parses(self) -> None:
        entries = load_fallbacks(FALLBACKS_YAML)
        assert len(entries) == 8

    @pytest.mark.parametrize(
        ("channel", "event_id", "event_action", "expected"),
        [
            ("Security", 1102, None, "T1070.001"),
            ("System", 104, None, "T1070.001"),
            ("Security", 4720, None, "T1136.001"),
            ("Security", 4698, None, "T1053.005"),
            ("System", 7045, None, "T1543.003"),
            (None, None, "ssh_failed_password", "T1110.001"),
            (None, None, "user_added", "T1136.001"),
            (None, None, "crontab_modified", "T1053.003"),
        ],
    )
    def test_each_shipped_entry_matches_its_event(
        self,
        channel: str | None,
        event_id: int | None,
        event_action: str | None,
        expected: str,
    ) -> None:
        entries = load_fallbacks(FALLBACKS_YAML)
        assert match_fallback(
            entries, channel=channel, event_id=event_id, event_action=event_action
        ) == (expected,)

    def test_channel_comparison_is_case_insensitive(self) -> None:
        entries = load_fallbacks(FALLBACKS_YAML)
        assert match_fallback(entries, channel="security", event_id=1102, event_action=None) == (
            "T1070.001",
        )

    def test_a_non_matching_event_maps_nothing(self) -> None:
        entries = load_fallbacks(FALLBACKS_YAML)
        assert match_fallback(entries, channel="Security", event_id=4688, event_action=None) == ()

    def test_an_entry_without_a_condition_is_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "fallbacks.yaml"
        path.write_text("- when: {}\n  techniques: [T1000]\n", encoding="utf-8")
        with pytest.raises(ValueError, match="no recognisable condition"):
            load_fallbacks(path)

    def test_a_malformed_document_is_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "fallbacks.yaml"
        path.write_text("not: a list\n", encoding="utf-8")
        with pytest.raises(TypeError, match="must be a list"):
            load_fallbacks(path)

    def test_a_missing_file_maps_nothing(self, tmp_path: Path) -> None:
        assert load_fallbacks(tmp_path / "absent.yaml") == ()


# --------------------------------------------------------------------------
# Per-alert resolution
# --------------------------------------------------------------------------


class TestAlertResolution:
    def test_rule_tags_win_over_the_fallback(self, database: Database) -> None:
        mapping = resolve_alert_mitre(
            ["attack.t1059.001"],
            catalogue=_catalogue(database),
            fallback_entries=load_fallbacks(FALLBACKS_YAML),
            channel="Security",
            event_id=1102,
        )
        assert mapping.source == "tag"
        assert [technique.id for technique in mapping.techniques] == ["T1059.001"]
        assert mapping.tactics == ("execution",)

    def test_fallback_covers_a_tagless_rule(self, database: Database) -> None:
        mapping = resolve_alert_mitre(
            [],
            catalogue=_catalogue(database),
            fallback_entries=load_fallbacks(FALLBACKS_YAML),
            channel="Security",
            event_id=1102,
        )
        assert mapping.source == "fallback"
        assert [technique.id for technique in mapping.techniques] == ["T1070.001"]
        assert mapping.tactics == ("defense-evasion",)

    def test_unresolved_only_tags_still_reach_the_fallback(self, database: Database) -> None:
        mapping = resolve_alert_mitre(
            ["attack.t9999"],
            catalogue=_catalogue(database),
            fallback_entries=load_fallbacks(FALLBACKS_YAML),
            channel="Security",
            event_id=1102,
        )
        assert mapping.source == "fallback"
        assert mapping.unresolved_tags == ("attack.t9999",)

    def test_explicit_tactic_tags_are_kept_verbatim(self, database: Database) -> None:
        mapping = resolve_alert_mitre(
            ["attack.t1110.001", "attack.credential_access"],
            catalogue=_catalogue(database),
        )
        assert mapping.tactics == ("credential-access",)

    def test_groups_and_software_become_context_chips(self, database: Database) -> None:
        mapping = resolve_alert_mitre(
            ["attack.g0032", "attack.s0002"], catalogue=_catalogue(database)
        )
        assert [entity.id for entity in mapping.groups_software] == ["G0032", "S0002"]

    def test_an_unmappable_alert_stays_empty(self, database: Database) -> None:
        mapping = resolve_alert_mitre([], catalogue=_catalogue(database))
        assert mapping.source == "none"
        assert mapping.techniques == ()
        assert mapping.tactics == ()


# --------------------------------------------------------------------------
# Enrichment storage
# --------------------------------------------------------------------------


class TestEnrichRunAlerts:
    def _prepare(self, database: Database) -> None:
        _seed_case(database)
        database.writer.execute(
            "INSERT INTO sources (id, case_id, filename, stored_path, size_bytes, "
            "sha256, status, ingested_at) VALUES ('src-1', 'case-1', 'a.log', "
            "'/tmp/a.log', 0, 'deadbeef', 'done', ?)",
            (_ISO,),
        )

    def test_a_tagged_rule_is_stored_with_source_tag(self, database: Database) -> None:
        self._prepare(database)
        _catalogue(database)
        _insert_alert(database, "alert-1")
        rules = {"rule-1": _rule_with_tags("rule-1", ("attack.t1110.001",))}
        count = enrich_run_alerts(
            database.writer,
            case_id="case-1",
            run_id="run-1",
            rules=rules,
            fallback_entries=load_fallbacks(FALLBACKS_YAML),
        )
        assert count == 1
        row = database.writer.execute(
            "SELECT tactics_json, techniques_json FROM alerts WHERE id = 'alert-1'"
        ).fetchone()
        assert row is not None
        assert json.loads(row["tactics_json"]) == ["credential-access"]
        techniques = json.loads(row["techniques_json"])
        assert techniques == [{"id": "T1110.001", "name": "Password Guessing", "source": "tag"}]

    def test_an_untagged_rule_falls_back_to_its_evidence(self, database: Database) -> None:
        self._prepare(database)
        _catalogue(database)
        _insert_alert(database, "alert-2")
        _insert_event(database, 1, channel="Security", sigma_event_id=1102)
        _link_alert_event(database, "alert-2", 1)
        enrich_run_alerts(
            database.writer,
            case_id="case-1",
            run_id="run-1",
            rules={"rule-1": _rule_with_tags("rule-1", ())},
            fallback_entries=load_fallbacks(FALLBACKS_YAML),
        )
        row = database.writer.execute(
            "SELECT techniques_json FROM alerts WHERE id = 'alert-2'"
        ).fetchone()
        assert row is not None
        techniques = json.loads(row["techniques_json"])
        assert techniques[0]["id"] == "T1070.001"
        assert techniques[0]["source"] == "fallback"

    def test_an_alert_without_mapping_keeps_empty_json(self, database: Database) -> None:
        self._prepare(database)
        _catalogue(database)
        _insert_alert(database, "alert-3")
        enrich_run_alerts(
            database.writer,
            case_id="case-1",
            run_id="run-1",
            rules={"rule-1": _rule_with_tags("rule-1", ())},
            fallback_entries=load_fallbacks(FALLBACKS_YAML),
        )
        row = database.writer.execute(
            "SELECT tactics_json, techniques_json, groups_software_json "
            "FROM alerts WHERE id = 'alert-3'"
        ).fetchone()
        assert row is not None
        assert json.loads(row["tactics_json"]) == []
        assert json.loads(row["techniques_json"]) == []
        assert json.loads(row["groups_software_json"]) == []

    def test_the_run_returns_zero_when_it_has_no_alerts(self, database: Database) -> None:
        self._prepare(database)
        _catalogue(database)
        count = enrich_run_alerts(database.writer, case_id="case-1", run_id="run-1", rules={})
        assert count == 0


# --------------------------------------------------------------------------
# Matrix aggregation
# --------------------------------------------------------------------------


class TestMatrix:
    def _seed(self, database: Database) -> None:
        _seed_case(database)
        _catalogue(database)

    def _matrix(self, database: Database) -> dict[str, Any]:
        return matrix_for_case(database.writer, case_id="case-1")

    def _technique(self, payload: dict[str, Any], tactic: str, attack_id: str) -> Any:
        for row in payload["tactics"]:
            if row["shortname"] != tactic:
                continue
            for technique in row["techniques"]:
                if technique["id"] == attack_id:
                    return technique
        return None

    def test_tactics_appear_in_canonical_order(self, database: Database) -> None:
        self._seed(database)
        payload = self._matrix(database)
        assert [row["shortname"] for row in payload["tactics"]] == [
            "reconnaissance",
            "resource-development",
            "initial-access",
            "execution",
            "persistence",
            "privilege-escalation",
            "defense-evasion",
            "credential-access",
            "discovery",
            "lateral-movement",
            "collection",
            "command-and-control",
            "exfiltration",
            "impact",
        ]

    def test_declared_tactics_win_over_the_techniques_own(self, database: Database) -> None:
        self._seed(database)
        _insert_alert(
            database,
            "alert-1",
            tactics=("execution",),
            technique_ids=("T1059",),
        )
        payload = self._matrix(database)
        assert self._technique(payload, "execution", "T1059") is not None
        assert self._technique(payload, "persistence", "T1059") is None

    def test_an_undeclared_alert_spans_every_own_tactic(self, database: Database) -> None:
        self._seed(database)
        _insert_alert(database, "alert-2", technique_ids=("T1059",))
        payload = self._matrix(database)
        assert self._technique(payload, "execution", "T1059") is not None
        assert self._technique(payload, "persistence", "T1059") is not None

    def test_a_subtechnique_nests_under_and_credits_its_parent(self, database: Database) -> None:
        self._seed(database)
        _insert_alert(database, "alert-3", technique_ids=("T1059.001",))
        payload = self._matrix(database)
        parent = self._technique(payload, "execution", "T1059")
        assert parent is not None
        assert parent["alert_ids"] == ["alert-3"]
        assert [sub["id"] for sub in parent["subtechniques"]] == ["T1059.001"]
        assert self._technique(payload, "persistence", "T1059") is not None

    def test_max_level_and_counts_roll_up(self, database: Database) -> None:
        self._seed(database)
        _insert_alert(database, "alert-4", level="medium", technique_ids=("T1110",))
        _insert_alert(database, "alert-5", level="critical", technique_ids=("T1110",))
        payload = self._matrix(database)
        technique = self._technique(payload, "credential-access", "T1110")
        assert technique is not None
        assert technique["alert_count"] == 2
        assert technique["max_level"] == "critical"
        assert technique["alert_ids"] == ["alert-4", "alert-5"]

    def test_unmapped_alerts_are_counted(self, database: Database) -> None:
        self._seed(database)
        _insert_alert(database, "alert-6")
        payload = self._matrix(database)
        assert payload["unmapped_alert_count"] == 1

    def test_attack_version_comes_from_mitre_meta(self, database: Database) -> None:
        self._seed(database)
        payload = self._matrix(database)
        assert payload["attack_version"] == "16.1.0"

    def test_alert_mappings_expose_stored_ids(self, database: Database) -> None:
        self._seed(database)
        _insert_alert(database, "alert-7", technique_ids=("T1110",), level="low")
        mappings = load_alert_mappings(database.writer, case_id="case-1")
        assert [mapping.id for mapping in mappings] == ["alert-7"]
        assert mappings[0].techniques == ("T1110",)
        assert mappings[0].level == "low"


# --------------------------------------------------------------------------
# Navigator layer
# --------------------------------------------------------------------------


class TestNavigator:
    def _catalogue_maps(
        self, catalogue: MitreCatalogue
    ) -> tuple[dict[str, str], dict[str, tuple[str, ...]]]:
        parent_of = {
            info.attack_id: info.parent_id
            for info in catalogue.techniques.values()
            if info.parent_id is not None
        }
        own = {info.attack_id: info.tactics for info in catalogue.techniques.values()}
        return parent_of, own

    def _layer(
        self,
        database: Database,
        mappings: tuple[Any, ...],
        **kwargs: Any,
    ) -> dict[str, Any]:
        parent_of, own = self._catalogue_maps(_catalogue(database))
        return build_layer(
            case_name="case-1",
            attack_version="16.1.0",
            mappings=mappings,
            parent_of=parent_of,
            own_tactics=own,
            generated_at="2026-01-01T00:00:00.000Z",
            **kwargs,
        )

    def test_layer_envelope_matches_the_spec(self, database: Database) -> None:
        _seed_case(database)
        layer = self._layer(database, ())
        assert layer["name"] == "TriageLens - case-1"
        assert layer["versions"] == {"attack": "16", "navigator": "5.1.0", "layer": "4.5"}
        assert layer["domain"] == "enterprise-attack"
        assert layer["sorting"] == 3
        assert layer["techniques"] == []

    def test_scores_follow_the_severity_ordinals(self, database: Database) -> None:
        _seed_case(database)
        _catalogue(database)
        _insert_alert(database, "a1", level="critical", technique_ids=("T1110",))
        _insert_alert(database, "a2", level="medium", technique_ids=("T1110",))
        mappings = load_alert_mappings(database.writer, case_id="case-1")
        layer = self._layer(database, mappings)
        (entry,) = layer["techniques"]
        assert entry["techniqueID"] == "T1110"
        assert entry["tactic"] == "credential-access"
        assert entry["score"] == 4
        assert entry["comment"].startswith("2 alerts; max level critical; rules:")

    def test_one_entry_per_technique_and_tactic_pair(self, database: Database) -> None:
        _seed_case(database)
        _catalogue(database)
        _insert_alert(database, "a3", technique_ids=("T1059",))
        mappings = load_alert_mappings(database.writer, case_id="case-1")
        layer = self._layer(database, mappings)
        pairs = {(entry["techniqueID"], entry["tactic"]) for entry in layer["techniques"]}
        assert pairs == {("T1059", "execution"), ("T1059", "persistence")}

    def test_a_subtechnique_alert_also_emits_its_parent(self, database: Database) -> None:
        _seed_case(database)
        _catalogue(database)
        _insert_alert(database, "a4", technique_ids=("T1059.001",))
        mappings = load_alert_mappings(database.writer, case_id="case-1")
        layer = self._layer(database, mappings)
        by_id = {(entry["techniqueID"], entry["tactic"]): entry for entry in layer["techniques"]}
        assert ("T1059.001", "execution") in by_id
        parent = by_id[("T1059", "execution")]
        assert parent["comment"].startswith("via sub-technique; 1 alert;")

    def test_comments_stay_within_the_length_limit(self, database: Database) -> None:
        _seed_case(database)
        _catalogue(database)
        for index in range(40):
            _insert_alert(
                database,
                f"a{index}",
                technique_ids=("T1110",),
                rule_title=f"Very Long Rule Title Number {index:02d} " + "x" * 30,
            )
        mappings = load_alert_mappings(database.writer, case_id="case-1")
        layer = self._layer(database, mappings)
        assert all(len(entry["comment"]) <= 500 for entry in layer["techniques"])

    def test_generation_is_deterministic(self, database: Database) -> None:
        _seed_case(database)
        _catalogue(database)
        _insert_alert(database, "a5", technique_ids=("T1110.001",))
        mappings = load_alert_mappings(database.writer, case_id="case-1")
        first = self._layer(database, mappings)
        second = self._layer(database, mappings)
        assert first == second

    def test_the_layer_validates_against_the_vendored_schema(self, database: Database) -> None:
        _seed_case(database)
        _catalogue(database)
        _insert_alert(database, "a6", level="high", technique_ids=("T1110.001",))
        mappings = load_alert_mappings(database.writer, case_id="case-1")
        layer = self._layer(database, mappings)
        schema = json.loads(LAYER_SCHEMA.read_text(encoding="utf-8"))
        assert _validate(layer, schema) == []


# --------------------------------------------------------------------------
# A minimal JSON Schema (draft-07) subset validator for the vendored layer
# schema - enough to check types, required keys, enums, patterns and bounds
# without pulling a compiled dependency onto the host.
# --------------------------------------------------------------------------


def _validate(instance: Any, schema: dict[str, Any], path: str = "$") -> list[str]:
    errors: list[str] = []
    expected = schema.get("type")
    if expected is not None and not _is_type(instance, expected):
        errors.append(f"{path}: expected {expected}, got {type(instance).__name__}")
        return errors
    errors.extend(_constraints(instance, schema, path))
    if isinstance(instance, dict):
        for key in schema.get("required", []):
            if key not in instance:
                errors.append(f"{path}: missing required property {key!r}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for key in instance:
                if key not in properties:
                    errors.append(f"{path}: unexpected property {key!r}")
        for key, subschema in properties.items():
            if key in instance:
                errors.extend(_validate(instance[key], subschema, f"{path}.{key}"))
    if isinstance(instance, list) and "items" in schema:
        items = schema["items"]
        for index, item in enumerate(instance):
            errors.extend(_validate(item, items, f"{path}[{index}]"))
    return errors


def _constraints(instance: Any, schema: dict[str, Any], path: str) -> list[str]:
    errors: list[str] = []
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: {instance!r} not in enum {schema['enum']}")
    if (
        "pattern" in schema
        and isinstance(instance, str)
        and not re.search(str(schema["pattern"]), instance)
    ):
        errors.append(f"{path}: {instance!r} fails pattern {schema['pattern']}")
    if (
        "minLength" in schema
        and isinstance(instance, str)
        and len(instance) < int(schema["minLength"])
    ):
        errors.append(f"{path}: shorter than minLength {schema['minLength']}")
    if (
        "minItems" in schema
        and isinstance(instance, list)
        and len(instance) < int(schema["minItems"])
    ):
        errors.append(f"{path}: fewer than minItems {schema['minItems']}")
    if (
        "minimum" in schema
        and isinstance(instance, (int, float))
        and not isinstance(instance, bool)
        and instance < schema["minimum"]
    ):
        errors.append(f"{path}: {instance} below minimum {schema['minimum']}")
    if (
        "maximum" in schema
        and isinstance(instance, (int, float))
        and not isinstance(instance, bool)
        and instance > schema["maximum"]
    ):
        errors.append(f"{path}: {instance} above maximum {schema['maximum']}")
    return errors


def _is_type(value: Any, expected: object) -> bool:
    if isinstance(expected, list):
        return any(_is_type(value, item) for item in expected)
    mapping: dict[str, Any] = {
        "object": dict,
        "array": list,
        "string": str,
        "boolean": bool,
        "integer": int,
        "number": (int, float),
        "null": type(None),
    }
    kind = mapping.get(str(expected))
    if kind is None:
        return True
    if isinstance(value, bool) and expected in {"integer", "number"}:
        return False
    return isinstance(value, kind)
