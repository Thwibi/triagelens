"""Audit chain: append-only enforcement, hash linking, and tamper detection."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Generator
from pathlib import Path

import pytest

from app.db.connection import Database
from app.db.migrations import apply_migrations
from app.db.repositories.audit import (
    AUDIT_GENESIS,
    AuditRepository,
    canonical_detail,
)

BACKEND_ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS_DIR = BACKEND_ROOT / "migrations"


@pytest.fixture
def audit(tmp_path: Path) -> Generator[tuple[AuditRepository, Database], None, None]:
    """A repository on a migrated database, plus the database for raw SQL."""
    database = Database(tmp_path / "t.db")
    apply_migrations(database.writer, MIGRATIONS_DIR)
    repository = AuditRepository(database.writer)
    try:
        yield repository, database
    finally:
        database.close()


def relink_tail(database: Database, from_id: int) -> str:
    """Rewrite ``prev_hash``/``hash`` from ``from_id`` onward, returning the new head.

    This models an attacker who understands the scheme and repairs the chain
    after editing a row. Callers must drop ``audit_log_block_update`` first.
    """
    from app.util.hashing import audit_chain_hash

    writer = database.writer
    previous = writer.execute(
        "SELECT hash FROM audit_log WHERE id < ? ORDER BY id DESC LIMIT 1", (from_id,)
    ).fetchone()
    prev_hash = str(previous[0]) if previous else AUDIT_GENESIS
    rows = writer.execute(
        "SELECT id, ts, action, detail_json FROM audit_log WHERE id >= ? ORDER BY id", (from_id,)
    ).fetchall()
    for row in rows:
        new_hash = audit_chain_hash(
            prev_hash, str(row["ts"]), str(row["action"]), str(row["detail_json"])
        )
        writer.execute(
            "UPDATE audit_log SET prev_hash = ?, hash = ? WHERE id = ?",
            (prev_hash, new_hash, int(row["id"])),
        )
        prev_hash = new_hash
    return prev_hash


class TestCanonicalDetail:
    def test_key_order_does_not_matter(self) -> None:
        assert canonical_detail({"a": 1, "b": 2}) == canonical_detail({"b": 2, "a": 1})

    def test_whitespace_does_not_matter(self) -> None:
        assert canonical_detail({"a": 1}) == '{"a":1}'

    def test_no_detail_becomes_an_empty_object(self) -> None:
        assert canonical_detail(None) == "{}"
        assert canonical_detail({}) == "{}"

    def test_unicode_is_not_escaped(self) -> None:
        assert canonical_detail({"k": "café"}) == '{"k":"café"}'

    def test_unserialisable_values_fall_back_to_repr(self) -> None:
        assert canonical_detail({"k": object}) is not None

    def test_nested_structures_are_sorted_recursively(self) -> None:
        left = canonical_detail({"outer": {"b": 1, "a": 2}})
        right = canonical_detail({"outer": {"a": 2, "b": 1}})
        assert left == right


class TestAppend:
    def test_an_empty_chain_is_genesis(self, audit: tuple[AuditRepository, Database]) -> None:
        repository, _ = audit
        assert repository.count() == 0
        assert repository.head() == AUDIT_GENESIS
        verification = repository.verify()
        assert verification.ok is True
        assert verification.rows_checked == 0
        assert verification.head_hash == AUDIT_GENESIS

    def test_appending_returns_the_stored_row(
        self, audit: tuple[AuditRepository, Database]
    ) -> None:
        repository, _ = audit
        entry = repository.append("case_created", case_id="c1", detail={"name": "x"})

        assert entry.action == "case_created"
        assert entry.case_id == "c1"
        assert entry.detail == {"name": "x"}
        assert entry.prev_hash == AUDIT_GENESIS
        assert len(entry.hash) == 64

    def test_each_row_links_to_the_previous_one(
        self, audit: tuple[AuditRepository, Database]
    ) -> None:
        repository, _ = audit
        first = repository.append("case_created", case_id="c1")
        second = repository.append("source_added", case_id="c1")
        third = repository.append("detection_run", case_id="c1")

        assert second.prev_hash == first.hash
        assert third.prev_hash == second.hash
        assert repository.head() == third.hash

    def test_rows_keep_insertion_order(self, audit: tuple[AuditRepository, Database]) -> None:
        repository, _ = audit
        for index in range(5):
            repository.append("case_created", case_id=f"c{index}")
        ids = [entry.id for entry in repository.iter_all()]
        assert ids == sorted(ids)

    def test_a_null_case_id_is_allowed(self, audit: tuple[AuditRepository, Database]) -> None:
        repository, _ = audit
        entry = repository.append("app_started")
        assert entry.case_id is None
        assert repository.verify().ok is True

    def test_a_supplied_timestamp_is_used_verbatim(
        self, audit: tuple[AuditRepository, Database]
    ) -> None:
        repository, _ = audit
        entry = repository.append("case_created", ts="2024-01-02T03:04:05.000000Z")
        assert entry.ts == "2024-01-02T03:04:05.000000Z"

    def test_unicode_and_control_characters_survive(
        self, audit: tuple[AuditRepository, Database]
    ) -> None:
        repository, _ = audit
        entry = repository.append("case_created", detail={"name": "café \u202e bidi \x00 null"})
        assert repository.verify().ok is True
        assert entry.detail is not None
        assert "\u202e" in str(entry.detail["name"])

    def test_a_large_detail_payload_is_accepted(
        self, audit: tuple[AuditRepository, Database]
    ) -> None:
        repository, _ = audit
        entry = repository.append("case_created", detail={"blob": "x" * 100_000})
        assert repository.verify().ok is True
        assert entry.detail is not None


class TestVerification:
    def test_a_clean_chain_verifies(self, audit: tuple[AuditRepository, Database]) -> None:
        repository, _ = audit
        for index in range(10):
            repository.append("case_created", case_id=f"c{index}", detail={"i": index})

        verification = repository.verify()
        assert verification.ok is True
        assert verification.rows_checked == 10
        assert verification.broken_at is None

    def test_filtering_by_case_still_counts_only_that_case(
        self, audit: tuple[AuditRepository, Database]
    ) -> None:
        repository, _ = audit
        repository.append("case_created", case_id="c1")
        repository.append("case_created", case_id="c2")
        repository.append("source_added", case_id="c1")

        verification = repository.verify(case_id="c1")
        assert verification.ok is True
        assert verification.rows_checked == 2


class TestTamperDetection:
    def test_updating_a_row_is_impossible(self, audit: tuple[AuditRepository, Database]) -> None:
        repository, database = audit
        entry = repository.append("case_created", case_id="c1")

        with pytest.raises(sqlite3.IntegrityError):
            database.writer.execute(
                "UPDATE audit_log SET action = 'tampered' WHERE id = ?", (entry.id,)
            )

    def test_deleting_a_row_is_impossible(self, audit: tuple[AuditRepository, Database]) -> None:
        repository, database = audit
        entry = repository.append("case_created", case_id="c1")

        with pytest.raises(sqlite3.IntegrityError):
            database.writer.execute("DELETE FROM audit_log WHERE id = ?", (entry.id,))

    def test_the_immutability_triggers_are_present(
        self, audit: tuple[AuditRepository, Database]
    ) -> None:
        repository, _ = audit
        repository.assert_append_only()

    def test_tampering_is_detected_after_the_triggers_are_dropped(
        self, audit: tuple[AuditRepository, Database]
    ) -> None:
        """With enforcement removed, the hash chain must still catch the edit."""
        repository, database = audit
        first = repository.append("case_created", case_id="c1")
        repository.append("source_added", case_id="c1")

        database.writer.execute("DROP TRIGGER audit_log_block_update")
        database.writer.execute(
            "UPDATE audit_log SET action = 'tampered' WHERE id = ?", (first.id,)
        )

        verification = repository.verify()
        assert verification.ok is False
        assert verification.broken_at == first.id
        assert "hash does not match" in (verification.broken_reason or "")

    def test_deleting_a_row_is_detected_after_the_trigger_is_dropped(
        self, audit: tuple[AuditRepository, Database]
    ) -> None:
        repository, database = audit
        first = repository.append("case_created", case_id="c1")
        repository.append("source_added", case_id="c1")

        database.writer.execute("DROP TRIGGER audit_log_block_delete")
        database.writer.execute("DELETE FROM audit_log WHERE id = ?", (first.id,))

        verification = repository.verify()
        assert verification.ok is False
        assert verification.broken_reason is not None

    def test_editing_the_detail_payload_is_detected(
        self, audit: tuple[AuditRepository, Database]
    ) -> None:
        repository, database = audit
        entry = repository.append("case_created", detail={"verdict": "benign"})
        database.writer.execute("DROP TRIGGER audit_log_block_update")
        database.writer.execute(
            "UPDATE audit_log SET detail_json = ? WHERE id = ?",
            (json.dumps({"verdict": "malicious"}), entry.id),
        )

        verification = repository.verify()
        assert verification.ok is False
        assert verification.broken_at == entry.id

    def test_editing_the_timestamp_is_detected(
        self, audit: tuple[AuditRepository, Database]
    ) -> None:
        repository, database = audit
        entry = repository.append("case_created")
        database.writer.execute("DROP TRIGGER audit_log_block_update")
        database.writer.execute(
            "UPDATE audit_log SET ts = ? WHERE id = ?", ("1999-01-01T00:00:00.000000Z", entry.id)
        )

        assert repository.verify().ok is False

    def test_a_locally_relinked_chain_stays_self_consistent(
        self, audit: tuple[AuditRepository, Database]
    ) -> None:
        """A bare hash chain cannot detect a fully rewritten history.

        This records the real limitation rather than asserting a false guarantee:
        an attacker who edits a row and recomputes every later ``prev_hash`` and
        ``hash`` produces a chain that verifies. Detection of that case depends on
        the external anchor, covered by the tombstone test below, plus the
        immutability triggers that make the edit require dropping them first.
        """
        repository, database = audit
        first = repository.append("case_created", case_id="c1")
        repository.append("source_added", case_id="c1")

        database.writer.execute("DROP TRIGGER audit_log_block_update")
        database.writer.execute(
            "UPDATE audit_log SET action = 'tampered' WHERE id = ?", (first.id,)
        )
        relink_tail(database, first.id)

        verification = repository.verify()
        assert verification.ok is True

    def test_a_recorded_head_exposes_a_relinked_chain(
        self, audit: tuple[AuditRepository, Database]
    ) -> None:
        """Comparing the live head against a recorded anchor catches the rewrite."""
        repository, database = audit
        first = repository.append("case_created", case_id="c1")
        repository.append("source_added", case_id="c1")
        anchor = repository.head()

        database.writer.execute("DROP TRIGGER audit_log_block_update")
        database.writer.execute(
            "UPDATE audit_log SET action = 'tampered' WHERE id = ?", (first.id,)
        )
        new_head = relink_tail(database, first.id)

        assert new_head != anchor
        assert repository.head() != anchor

    def test_the_head_hash_is_reported_for_recovery(
        self, audit: tuple[AuditRepository, Database]
    ) -> None:
        repository, database = audit
        first = repository.append("case_created", case_id="c1")
        repository.append("source_added", case_id="c1")
        database.writer.execute("DROP TRIGGER audit_log_block_update")
        database.writer.execute(
            "UPDATE audit_log SET action = 'tampered' WHERE id = ?", (first.id,)
        )

        verification = repository.verify()
        assert verification.head_hash == first.prev_hash
        assert len(verification.head_hash) == 64


class TestListing:
    def test_paging_defaults_to_newest_first(self, audit: tuple[AuditRepository, Database]) -> None:
        repository, _ = audit
        for index in range(5):
            repository.append("case_created", case_id=f"c{index}")

        page = repository.list_page(limit=2)
        assert [entry.id for entry in page] == sorted(
            (entry.id for entry in repository.iter_all()), reverse=True
        )[:2]

    def test_ascending_order_is_available(self, audit: tuple[AuditRepository, Database]) -> None:
        repository, _ = audit
        for index in range(3):
            repository.append("case_created", case_id=f"c{index}")
        ids = [entry.id for entry in repository.list_page(order="asc")]
        assert ids == sorted(ids)

    def test_an_unknown_order_falls_back_to_descending(
        self, audit: tuple[AuditRepository, Database]
    ) -> None:
        repository, _ = audit
        repository.append("case_created")
        assert len(repository.list_page(order="sideways")) == 1

    def test_filtering_by_case(self, audit: tuple[AuditRepository, Database]) -> None:
        repository, _ = audit
        repository.append("case_created", case_id="c1")
        repository.append("case_created", case_id="c2")
        repository.append("source_added", case_id="c1")

        assert len(repository.list_page(case_id="c1")) == 2
        assert len(repository.list_page(case_id="c2")) == 1
        assert len(repository.list_page(case_id="absent")) == 0

    def test_offset_pages_through_the_log(self, audit: tuple[AuditRepository, Database]) -> None:
        repository, _ = audit
        for index in range(6):
            repository.append("case_created", case_id=f"c{index}")

        first = repository.list_page(limit=3, offset=0, order="asc")
        second = repository.list_page(limit=3, offset=3, order="asc")
        assert len(first) == 3
        assert len(second) == 3
        assert {entry.id for entry in first}.isdisjoint({entry.id for entry in second})

    def test_count_filters_by_case(self, audit: tuple[AuditRepository, Database]) -> None:
        repository, _ = audit
        repository.append("case_created", case_id="c1")
        repository.append("case_created", case_id="c2")

        assert repository.count() == 2
        assert repository.count(case_id="c1") == 1
        assert repository.count(case_id="absent") == 0


class TestTombstones:
    def test_a_tombstone_records_the_chain_head(
        self, audit: tuple[AuditRepository, Database]
    ) -> None:
        repository, _ = audit
        repository.append("case_created", case_id="c1")
        repository.append("source_added", case_id="c1")
        head = repository.head()
        count = repository.count(case_id="c1")

        tombstone = repository.write_tombstone(case_id="c1", last_hash=head, row_count=count)

        assert tombstone.case_id == "c1"
        assert tombstone.last_hash == head
        assert tombstone.row_count == 2
        assert tombstone.deleted_at.endswith("Z")

    def test_tombstones_are_listed_newest_first(
        self, audit: tuple[AuditRepository, Database]
    ) -> None:
        repository, _ = audit
        repository.write_tombstone(case_id="c1", last_hash="a" * 64, row_count=1)
        repository.write_tombstone(case_id="c2", last_hash="b" * 64, row_count=2)

        assert [item.case_id for item in repository.tombstones()] == ["c2", "c1"]
        assert [item.case_id for item in repository.tombstones(case_id="c1")] == ["c1"]

    def test_a_tombstone_does_not_disturb_the_chain(
        self, audit: tuple[AuditRepository, Database]
    ) -> None:
        repository, _ = audit
        repository.append("case_created", case_id="c1")
        repository.write_tombstone(case_id="c1", last_hash=repository.head(), row_count=1)
        assert repository.verify().ok is True
