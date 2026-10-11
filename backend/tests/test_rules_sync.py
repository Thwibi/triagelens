"""Rules catalogue sync: startup bootstrap and full import refresh.

A fresh install starts with an empty ``rules`` table, so detection has nothing
to run. ``sync_catalogue`` loads the shipped builtin and sigma trees plus the
custom directory through the engine's own loader and reconciles the catalogue
(spec 04 section 1). These tests pin that the sync is idempotent by rule id,
never touches ``enabled``, removes stale shipped rows without ever deleting
custom ones, and that the ``sync_rules_on_startup`` bootstrap seeds the tree
once and skips every later boot.
"""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from app.config import Settings
from app.db.connection import Database
from app.db.repositories.audit import AuditRepository
from app.db.repositories.rules import RuleRepository
from app.detect.sync import sync_catalogue
from app.main import create_app
from app.models.rule import KIND_BUILTIN, KIND_CUSTOM, KIND_SIGMA

BACKEND_ROOT = Path(__file__).resolve().parents[1]
#: The shipped tree is the source of truth; these tests sign the whole thing.
_BUILTIN_DIR = BACKEND_ROOT / "rules" / "builtin"
_MAP = BACKEND_ROOT / "rules" / "logsource_map.yaml"

#: Catalogue size grown by a full startup sync: 16 builtin + 374 SigmaHQ.
_SHIPPED = 16
_SIGMA = 374
_TOTAL = _SHIPPED + _SIGMA


def _doc(rule_id: str, title: str = "Example Rule") -> str:
    """A minimal rule that parses, compiles and routes to ``webserver``."""
    return (
        f"title: {title}\n"
        f"id: {rule_id}\n"
        "status: stable\n"
        "logsource: { category: webserver }\n"
        "detection:\n"
        "  selection:\n"
        "    cs-method: POST\n"
        "  condition: selection\n"
        "level: high\n"
        "tags: [attack.t1190]\n"
    )


def _tree(tmp_path: Path) -> tuple[Path, Path, Path]:
    """Three empty scratch rule directories: builtin, sigma, custom."""
    directories = (tmp_path / "builtin", tmp_path / "sigma", tmp_path / "custom")
    for directory in directories:
        directory.mkdir()
    return directories


def _write(directory: Path, name: str, body: str) -> Path:
    path = directory / name
    path.write_text(body, encoding="utf-8")
    return path


class TestCatalogueSync:
    """Unit-level sync against scratch trees and the real logsource map."""

    def test_a_fresh_load_populates_the_catalogue(self, database: Database, tmp_path: Path) -> None:
        builtin, sigma, custom = _tree(tmp_path)
        _write(builtin, "a.yml", _doc("10000000-0000-0000-0000-000000000001"))
        _write(sigma, "s.yml", _doc("10000000-0000-0000-0000-000000000002"))
        _write(custom, "c.yml", _doc("10000000-0000-0000-0000-000000000003"))

        report = sync_catalogue(
            database.writer,
            builtin_dir=builtin,
            sigma_dir=sigma,
            custom_dir=custom,
            logsource_map=_MAP,
        )

        assert report.problems == ()
        assert report.upserted == 3
        assert report.stale_removed == 0
        assert report.total == 3
        assert report.kinds == {KIND_BUILTIN: 1, KIND_SIGMA: 1, KIND_CUSTOM: 1}
        repo = RuleRepository(database.writer)
        assert repo.count() == 3
        rule = repo.get("10000000-0000-0000-0000-000000000001")
        assert rule is not None
        assert rule.kind == KIND_BUILTIN
        rule = repo.get("10000000-0000-0000-0000-000000000002")
        assert rule is not None
        assert rule.kind == KIND_SIGMA
        rule = repo.get("10000000-0000-0000-0000-000000000003")
        assert rule is not None
        assert rule.kind == KIND_CUSTOM

    def test_sync_writes_one_audit_entry_with_the_report(
        self, database: Database, tmp_path: Path
    ) -> None:
        builtin, _, _ = _tree(tmp_path)
        _write(builtin, "a.yml", _doc("10000000-0000-0000-0000-000000000001"))

        sync_catalogue(
            database.writer,
            builtin_dir=builtin,
            logsource_map=_MAP,
        )

        entries = list(AuditRepository(database.writer).iter_all())
        assert len(entries) == 1
        entry = entries[0]
        assert entry.action == "rules_imported"
        assert entry.detail == {
            "action": "sync",
            "count": 1,
            "upserted": 1,
            "stale_removed": 0,
            "problems": 0,
        }

    def test_audit_can_be_suppressed(self, database: Database, tmp_path: Path) -> None:
        builtin, _, _ = _tree(tmp_path)
        _write(builtin, "a.yml", _doc("10000000-0000-0000-0000-000000000001"))

        sync_catalogue(
            database.writer,
            builtin_dir=builtin,
            logsource_map=_MAP,
            audit=False,
        )

        assert list(AuditRepository(database.writer).iter_all()) == []

    def test_resync_is_idempotent_and_keeps_enabled(
        self, database: Database, tmp_path: Path
    ) -> None:
        builtin, sigma, custom = _tree(tmp_path)
        _write(builtin, "a.yml", _doc("10000000-0000-0000-0000-000000000001"))
        _write(sigma, "s.yml", _doc("10000000-0000-0000-0000-000000000002"))
        _write(custom, "c.yml", _doc("10000000-0000-0000-0000-000000000003"))
        sync_catalogue(
            database.writer,
            builtin_dir=builtin,
            sigma_dir=sigma,
            custom_dir=custom,
            logsource_map=_MAP,
        )
        repo = RuleRepository(database.writer)
        assert repo.set_enabled("10000000-0000-0000-0000-000000000001", enabled=False)

        report = sync_catalogue(
            database.writer,
            builtin_dir=builtin,
            sigma_dir=sigma,
            custom_dir=custom,
            logsource_map=_MAP,
        )

        assert report.problems == ()
        assert report.total == 3
        assert repo.count() == 3
        record = repo.get("10000000-0000-0000-0000-000000000001")
        assert record is not None
        assert record.enabled is False, "a reload must never re-enable a rule someone switched off"

    def test_stale_shipped_rows_are_removed_but_custom_rows_survive(
        self, database: Database, tmp_path: Path
    ) -> None:
        builtin, sigma, custom = _tree(tmp_path)
        _write(builtin, "a.yml", _doc("10000000-0000-0000-0000-000000000001"))
        _write(sigma, "s.yml", _doc("10000000-0000-0000-0000-000000000002"))
        _write(custom, "keep.yml", _doc("10000000-0000-0000-0000-000000000003"))
        sync_catalogue(
            database.writer,
            builtin_dir=builtin,
            sigma_dir=sigma,
            custom_dir=custom,
            logsource_map=_MAP,
        )

        # The shipped tree changed under us (renames/removals), and the operator
        # deleted their custom file. The sync must mirror the shipped sets from
        # disk while leaving custom rows strictly alone.
        (builtin / "a.yml").unlink()
        _write(builtin, "b.yml", _doc("10000000-0000-0000-0000-000000000004", title="New One"))
        (sigma / "s.yml").unlink()
        _write(sigma, "t.yml", _doc("10000000-0000-0000-0000-000000000005"))
        (custom / "keep.yml").unlink()

        report = sync_catalogue(
            database.writer,
            builtin_dir=builtin,
            sigma_dir=sigma,
            custom_dir=custom,
            logsource_map=_MAP,
        )

        assert report.stale_removed == 2
        assert report.total == 2
        assert report.kinds == {KIND_BUILTIN: 1, KIND_SIGMA: 1}
        repo = RuleRepository(database.writer)
        assert repo.count() == 3
        assert repo.get("10000000-0000-0000-0000-000000000001") is None
        assert repo.get("10000000-0000-0000-0000-000000000002") is None
        rule = repo.get("10000000-0000-0000-0000-000000000004")
        assert rule is not None
        assert rule.kind == KIND_BUILTIN
        rule = repo.get("10000000-0000-0000-0000-000000000005")
        assert rule is not None
        assert rule.kind == KIND_SIGMA
        # The custom row stays even though its file was deleted: only an explicit
        # DELETE /rules/{id} (which also removes the file) removes a custom rule.
        assert repo.get("10000000-0000-0000-0000-000000000003") is not None

    def test_everything_works_when_only_custom_exists_for_a_while(
        self, database: Database, tmp_path: Path
    ) -> None:
        _, _, custom = _tree(tmp_path)
        _write(custom, "c.yml", _doc("10000000-0000-0000-0000-000000000003"))

        report = sync_catalogue(
            database.writer,
            builtin_dir=None,
            sigma_dir=None,
            custom_dir=custom,
            logsource_map=_MAP,
        )

        assert report.problems == ()
        assert report.total == 1
        assert report.kinds == {KIND_CUSTOM: 1}
        assert RuleRepository(database.writer).count() == 1

    def test_a_broken_document_is_reported_not_fatal(
        self, database: Database, tmp_path: Path
    ) -> None:
        builtin, sigma, custom = _tree(tmp_path)
        _write(builtin, "a.yml", _doc("10000000-0000-0000-0000-000000000001"))
        _write(sigma, "broken.yml", "title: broken\ndetection: [\n")
        _write(custom, "c.yml", _doc("10000000-0000-0000-0000-000000000003"))

        report = sync_catalogue(
            database.writer,
            builtin_dir=builtin,
            sigma_dir=sigma,
            custom_dir=custom,
            logsource_map=_MAP,
        )

        assert len(report.problems) == 1
        assert report.problems[0].where.endswith("broken.yml")
        assert report.total == 2
        repo = RuleRepository(database.writer)
        assert repo.count() == 2
        assert repo.get("10000000-0000-0000-0000-000000000001") is not None

    def test_load_problems_never_prune_anything(self, database: Database, tmp_path: Path) -> None:
        builtin, _, _ = _tree(tmp_path)
        _write(builtin, "a.yml", _doc("10000000-0000-0000-0000-000000000001"))
        sync_catalogue(database.writer, builtin_dir=builtin, logsource_map=_MAP)

        report = sync_catalogue(
            database.writer,
            builtin_dir=builtin,
            sigma_dir=tmp_path / "sigma",
            logsource_map=_MAP,
        )

        # The broken/missing sources contribute nothing to ``keep``, but the rows
        # already in the catalogue are reconciled against this run's loaded ids
        # and must come out untouched when nothing shipped was removed.
        assert report.problems == ()
        assert report.stale_removed == 0
        assert report.total == 1


def _settings(data_dir: Path, *, sync: bool) -> Settings:
    return Settings(
        server={"host": "127.0.0.1", "port": 8787},
        storage={"data_dir": str(data_dir)},
        logging={"console": False, "level": "CRITICAL"},
        detection={"sync_rules_on_startup": sync},
    )


def _start(data_dir: Path, *, sync: bool) -> TestClient:
    data_dir.mkdir(parents=True, exist_ok=True)
    return TestClient(create_app(_settings(data_dir, sync=sync)), base_url="http://127.0.0.1:8787")


class TestStartupBootstrap:
    """The ``sync_rules_on_startup`` gate and the boots around it."""

    def test_first_boot_seeds_the_full_shipped_tree(self, tmp_path: Path) -> None:
        with _start(tmp_path / "data", sync=True) as client:
            builtin = client.get("/api/rules", params={"kind": KIND_BUILTIN, "limit": 1}).json()
            sigma = client.get("/api/rules", params={"kind": KIND_SIGMA, "limit": 1}).json()
            health = client.get("/api/rules/health").json()

        assert builtin["total"] == _SHIPPED
        assert sigma["total"] == _SIGMA
        assert health == {"ok": _TOTAL, "compile_error": 0, "unroutable": 0, "total": _TOTAL}

    def test_the_opt_out_leaves_the_catalogue_empty(self, tmp_path: Path) -> None:
        with _start(tmp_path / "data", sync=False) as client:
            listing = client.get("/api/rules", params={"limit": 100}).json()

        assert listing["total"] == 0

    def test_a_later_boot_skips_the_sync_and_keeps_enabled(self, tmp_path: Path) -> None:
        data_dir = tmp_path / "data"
        with _start(data_dir, sync=True) as client:
            first = client.get("/api/rules", params={"kind": KIND_SIGMA, "limit": 1}).json()
            rule_id = first["items"][0]["id"]
            response = client.patch(f"/api/rules/{rule_id}", json={"enabled": False})
            assert response.status_code == 200, response.text
            assert response.json()["item"]["enabled"] is False

        with _start(data_dir, sync=True) as client:
            # Rows already exist, so the 4-5 s tree load is skipped entirely;
            # the disabled flag is catalogue state and must have survived.
            after = client.get(f"/api/rules/{rule_id}").json()
            sigma = client.get("/api/rules", params={"kind": KIND_SIGMA, "limit": 1}).json()

        assert after["enabled"] is False
        assert sigma["total"] == _SIGMA

    def test_import_refreshes_the_whole_catalogue(self, tmp_path: Path) -> None:
        with _start(tmp_path / "data", sync=False) as client:
            response = client.post(
                "/api/rules/import",
                files={
                    "files": (
                        "extra.yml",
                        _doc("10000000-0000-0000-0000-000000000009", title="Extra"),
                        "application/yaml",
                    )
                },
            )
            assert response.status_code == 200, response.text
            body = response.json()
            assert body["imported"] == 1
            assert body["synced"] == _TOTAL + 1
            assert body["stale_removed"] == 0
            assert body["problems"] == []
            stored = client.get("/api/rules/10000000-0000-0000-0000-000000000009")

        assert stored.status_code == 200

    def test_import_writes_one_import_audit_entry_per_batch(self, tmp_path: Path) -> None:
        data_dir = tmp_path / "data"
        settings = _settings(data_dir, sync=False)
        with TestClient(create_app(settings), base_url="http://127.0.0.1:8787") as client:
            client.post(
                "/api/rules/import",
                files={
                    "files": (
                        "extra.yml",
                        _doc("10000000-0000-0000-0000-000000000009", title="Extra"),
                        "application/yaml",
                    )
                },
            )

        database = Database(settings.db_path)
        try:
            entries = list(AuditRepository(database.writer).iter_all())
        finally:
            database.close()
        imports = [entry for entry in entries if entry.action == "rules_imported"]
        assert len(imports) == 1
        assert imports[0].detail["action"] == "import"
        assert imports[0].detail["synced"] == _TOTAL + 1
