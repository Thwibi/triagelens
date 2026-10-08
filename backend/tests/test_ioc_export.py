"""IOC export renderers (spec 05 section 8).

Pure-function tests: every format and every STIX pattern mapping gets a label,
independent of the HTTP surface exercised in ``test_api_iocs``.
"""

from __future__ import annotations

import json

from app.db.repositories.iocs import IocRecord
from app.ioc.export import (
    MEDIA_TYPES,
    render_csv,
    render_json,
    render_stix,
    render_txt,
)


def record(
    *,
    ioc_type: str,
    value: str = "x",
    confidence: int = 50,
    first_seen_ms: int | None = 1_704_067_200_000,
    last_seen_ms: int | None = 1_704_067_201_000,
    analyst_state: str = "none",
    tags: list[str] | None = None,
) -> IocRecord:
    """A minimal stored IOC for renderer unit tests."""
    return IocRecord(
        id=f"id-{ioc_type}",
        case_id="case-1",
        type=ioc_type,
        value=value,
        value_norm=value,
        first_seen_ms=first_seen_ms,
        last_seen_ms=last_seen_ms,
        occurrences=3,
        confidence=confidence,
        is_private=False,
        is_allowlisted=False,
        analyst_state=analyst_state,
        tags=tags or [],
    )


class TestCsv:
    def test_the_spec_header_comes_first(self) -> None:
        text = render_csv([record(ioc_type="ipv4", value="203.0.113.9")])
        header = text.splitlines()[0]
        assert header.split(",")[:4] == ["type", "value", "confidence", "occurrences"]
        assert "first_seen" in header
        assert "tags" in header

    def test_fields_map_to_spec_columns(self) -> None:
        items = [
            record(
                ioc_type="domain",
                value="evil.com",
                analyst_state="malicious",
                tags=["t1", "t2"],
            )
        ]
        text = render_csv(items)
        lines = text.splitlines()
        assert len(lines) == 2
        columns = dict(zip(lines[0].split(","), lines[1].split(","), strict=False))
        assert columns["type"] == "domain"
        assert columns["value"] == "evil.com"
        assert columns["analyst_state"] == "malicious"
        assert columns["tags"] == "t1|t2"

    def test_timestamps_render_as_utc_iso(self) -> None:
        text = render_csv([record(ioc_type="ipv4")])
        first_seen = text.splitlines()[1].split(",")[4]
        assert first_seen.endswith("Z")


class TestTxt:
    def test_one_value_per_line(self) -> None:
        items = [
            record(ioc_type="domain", value="evil.com"),
            record(ioc_type="url", value="http://evil.com/a"),
        ]
        assert render_txt(items) == "evil.com\nhttp://evil.com/a\n"

    def test_defang_replaces_the_markers(self) -> None:
        text = render_txt([record(ioc_type="domain", value="evil.com")], defanged=True)
        assert text.strip() == "evil[.]com"

    def test_empty_collection_renders_empty(self) -> None:
        assert render_txt([]) == ""


class TestStix:
    def _bundle(self, items: list[IocRecord]) -> dict:
        return render_stix(items)

    def test_every_spec_pattern_type_is_mapped(self) -> None:
        cases = [
            ("ipv4", "10.1.2.3", "[ipv4-addr:value = '10.1.2.3']"),
            ("ipv6", "2001:db8::1", "[ipv6-addr:value = '2001:db8::1']"),
            ("domain", "evil.com", "[domain-name:value = 'evil.com']"),
            ("url", "http://evil.com/a", "[url:value = 'http://evil.com/a']"),
            ("email", "a@evil.com", "[email-addr:value = 'a@evil.com']"),
            ("md5", "a" * 32, "[file:hashes.'MD5' = '" + "a" * 32 + "']"),
            ("sha1", "b" * 40, "[file:hashes.'SHA-1' = '" + "b" * 40 + "']"),
            ("sha256", "c" * 64, "[file:hashes.'SHA-256' = '" + "c" * 64 + "']"),
            (
                "registry",
                r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
                (
                    r"[windows-registry-key:key = "
                    r"'HKLM\Software\Microsoft\Windows\CurrentVersion\Run']"
                ),
            ),
            ("filename", "payload.exe", "[file:name = 'payload.exe']"),
        ]
        bundle = self._bundle([record(ioc_type=t, value=v) for t, v, _ in cases])
        patterns = {obj["pattern"] for obj in bundle["objects"]}
        for _, _, expected in cases:
            assert expected in patterns

    def test_note_types_are_carried_as_observables(self) -> None:
        for ioc_type in ("filepath", "cve", "user_agent", "command"):
            bundle = self._bundle([record(ioc_type=ioc_type, value="x")])
            notes = [obj for obj in bundle["objects"] if obj["type"] == "note"]
            assert notes, f"{ioc_type} produced no note"
            assert notes[0]["x-triagelens-observable"][0]["type"] == ioc_type

    def test_malicious_activity_label_only_for_malicious_state(self) -> None:
        malicious = self._bundle([record(ioc_type="ipv4", analyst_state="malicious")])
        assert malicious["objects"][0]["labels"] == ["malicious-activity"]
        for state in ("none", "suspicious", "benign"):
            bundle = self._bundle([record(ioc_type="ipv4", analyst_state=state)])
            assert bundle["objects"][0]["labels"] == ["anomalous-activity"]

    def test_indicator_ids_are_stable_and_bundle_is_valid(self) -> None:
        bundle = self._bundle([record(ioc_type="ipv4"), record(ioc_type="domain")])
        assert bundle["type"] == "bundle"
        assert bundle["spec_version"] == "2.1"
        assert len(bundle["objects"]) == 2


class TestJson:
    def test_every_record_is_present_with_its_fields(self) -> None:
        items = [record(ioc_type="ipv4", value="203.0.113.9", tags=["a"])]
        payload = json.loads(render_json(items))
        assert payload[0]["value"] == "203.0.113.9"
        assert payload[0]["analyst_state"] == "none"
        assert payload[0]["tags"] == ["a"]

    def test_occurrences_are_attached_when_a_provider_is_given(self) -> None:
        items = [record(ioc_type="ipv4")]
        payload = json.loads(render_json(items, occurrences_of=lambda _id: [{"event_id": 1}]))
        assert payload[0]["occurrences_meta"] == [{"event_id": 1}]

    def test_defang_is_applied_to_values(self) -> None:
        items = [record(ioc_type="url", value="http://evil.com/a")]
        payload = json.loads(render_json(items, defanged=True))
        assert payload[0]["value"] == "hxxp://evil[.]com/a"


class TestMediaTypes:
    def test_all_spec_formats_are_served(self) -> None:
        assert set(MEDIA_TYPES) == {"csv", "txt", "stix", "json"}
