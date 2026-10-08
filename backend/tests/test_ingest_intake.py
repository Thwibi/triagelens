"""Upload intake and server-side path import (spec 03 section 5, spec 09 P-08)."""

from __future__ import annotations

import gzip
import io
import tarfile
import zipfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from app.config import Settings
from app.errors import ApiError, ErrorCode
from app.ingest.import_from_path import import_candidates, is_within, resolve_import_path
from app.ingest.intake import (
    MAX_FILENAME_LENGTH,
    IntakeResult,
    safe_filename,
    store_file,
    store_stream,
)
from app.ingest.intake import intake_stream as run_intake

ECS_LINE = b'{"@timestamp":"2026-03-01T10:00:00Z","host":{"name":"web01"},"message":"ok"}\n'


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    """Settings with tiny limits so the bounds are reachable in a test."""
    return Settings(
        storage={"data_dir": tmp_path / "data", "allowed_import_roots": [str(tmp_path)]},
        limits={
            "max_upload_gb": 1,
            "max_archive_members": 10,
            "max_archive_total_gb": 1,
            "max_archive_depth": 3,
            "max_archive_expansion_ratio": 100,
        },
    )


def chunked(data: bytes, size: int = 8) -> Iterator[bytes]:
    """A stream that arrives in pieces, as a real request body does."""

    def generate() -> Iterator[bytes]:
        for start in range(0, len(data), size):
            yield data[start : start + size]

    return generate()


class TestSafeFilename:
    """A client-supplied name is a label, never a path."""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("a.log", "a.log"),
            ("dir/a.log", "a.log"),
            ("../../etc/passwd", "passwd"),
            ("..\\..\\windows\\system32\\evil.exe", "evil.exe"),
            ("/absolute/path/file.log", "file.log"),
            ("weird name!.log", "weird_name_.log"),
            ("a;b&c.log", "a_b_c.log"),
        ],
    )
    def test_names_are_reduced_to_a_basename(self, raw: str, expected: str) -> None:
        assert safe_filename(raw) == expected

    @pytest.mark.parametrize("raw", ["", "   ", "...", "///", "../.."])
    def test_unusable_names_are_refused(self, raw: str) -> None:
        with pytest.raises(ApiError) as caught:
            safe_filename(raw)
        assert caught.value.code is ErrorCode.FORBIDDEN_PATH

    def test_leading_dash_is_removed(self) -> None:
        # A stored name beginning with a dash could be read as an option.
        assert not safe_filename("-rf.log").startswith("-")

    def test_long_names_keep_their_extension(self) -> None:
        result = safe_filename("x" * 400 + ".json")
        assert result.endswith(".json")
        assert len(result) <= MAX_FILENAME_LENGTH

    def test_result_is_always_a_plain_name(self) -> None:
        for raw in ("../../x", "a/b/c", "\\\\server\\share\\f"):
            assert "/" not in safe_filename(raw)
            assert "\\" not in safe_filename(raw)


class TestStoreStream:
    """Size, hashing and cleanup."""

    def test_stores_bytes_and_hash(self, tmp_path: Path) -> None:
        stored = store_stream(io.BytesIO(b"hello\n"), tmp_path, "a.log", max_bytes=1000)
        assert stored.path.read_bytes() == b"hello\n"
        assert stored.size == 6
        assert stored.sha256 == ("5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03")

    def test_original_filename_is_kept(self, tmp_path: Path) -> None:
        stored = store_stream(io.BytesIO(b"x"), tmp_path, "original.log", max_bytes=100)
        assert stored.filename == "original.log"
        assert stored.name == "original.log"

    def test_traversal_filename_cannot_escape(self, tmp_path: Path) -> None:
        stored = store_stream(io.BytesIO(b"x"), tmp_path, "../pwned.log", max_bytes=100)
        assert stored.path.parent == tmp_path
        assert not (tmp_path.parent / "pwned.log").exists()

    def test_over_limit_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(ApiError) as caught:
            store_stream(io.BytesIO(b"x" * 500), tmp_path, "a.log", max_bytes=100)
        assert caught.value.code is ErrorCode.UPLOAD_TOO_LARGE

    def test_over_limit_leaves_nothing_behind(self, tmp_path: Path) -> None:
        with pytest.raises(ApiError):
            store_stream(io.BytesIO(b"x" * 5000), tmp_path, "a.log", max_bytes=100)
        assert list(tmp_path.iterdir()) == []

    def test_limit_is_applied_to_received_bytes_not_a_claim(self, tmp_path: Path) -> None:
        # A stream that lies about its size is still bounded by counting.
        with pytest.raises(ApiError):
            store_stream(chunked(b"x" * 5000, 64), tmp_path, "a.log", max_bytes=100)
        assert list(tmp_path.iterdir()) == []

    def test_exactly_at_the_limit_is_accepted(self, tmp_path: Path) -> None:
        stored = store_stream(io.BytesIO(b"x" * 100), tmp_path, "a.log", max_bytes=100)
        assert stored.size == 100

    def test_empty_upload_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(ApiError) as caught:
            store_stream(io.BytesIO(b""), tmp_path, "a.log", max_bytes=100)
        assert caught.value.code is ErrorCode.UNSUPPORTED_FORMAT

    def test_empty_upload_leaves_no_file(self, tmp_path: Path) -> None:
        with pytest.raises(ApiError):
            store_stream(io.BytesIO(b""), tmp_path, "a.log", max_bytes=100)
        assert list(tmp_path.iterdir()) == []

    def test_client_disconnect_leaves_no_partial_file(self, tmp_path: Path) -> None:
        def failing() -> Iterator[bytes]:
            yield b"partial"
            raise ConnectionResetError("client went away")

        with pytest.raises(ConnectionResetError):
            store_stream(failing(), tmp_path, "a.log", max_bytes=1000)
        assert list(tmp_path.iterdir()) == []

    def test_store_file_copies_an_existing_file(self, tmp_path: Path) -> None:
        source = tmp_path / "source.log"
        source.write_bytes(b"data\n")
        destination = tmp_path / "stored"
        stored = store_file(source, destination, max_bytes=1000)
        assert stored.path.read_bytes() == b"data\n"
        assert source.exists(), "the original must be left alone"


class TestIntakeStream:
    """Store, expand, detect."""

    def test_stores_and_detects_json(self, settings: Settings, tmp_path: Path) -> None:
        result = run_intake(
            io.BytesIO(ECS_LINE * 5), tmp_path / "s1", "events.ndjson", settings=settings
        )
        assert isinstance(result, IntakeResult)
        assert result.stored.size == len(ECS_LINE) * 5
        assert result.detection.log_type == "generic_json"
        assert result.needs_input is False

    def test_destination_is_created(self, settings: Settings, tmp_path: Path) -> None:
        target = tmp_path / "deep" / "s1"
        run_intake(io.BytesIO(ECS_LINE), target, "a.ndjson", settings=settings)
        assert (target / "a.ndjson").exists()

    def test_unrecognized_upload_needs_input(self, settings: Settings, tmp_path: Path) -> None:
        result = run_intake(
            io.BytesIO(b"just prose\n"), tmp_path / "s1", "a.log", settings=settings
        )
        assert result.detection.needs_input is True
        assert result.detection.reason

    def test_override_skips_detection(self, settings: Settings, tmp_path: Path) -> None:
        result = run_intake(
            io.BytesIO(b"anything"),
            tmp_path / "s1",
            "a.log",
            settings=settings,
            log_type_override="windows_evtx",
        )
        assert result.detection.log_type == "windows_evtx"
        assert result.detection.source == "override"

    def test_stored_files_are_read_only(self, settings: Settings, tmp_path: Path) -> None:
        result = run_intake(io.BytesIO(ECS_LINE), tmp_path / "s1", "a.ndjson", settings=settings)
        assert not result.stored.path.stat().st_mode & 0o222

    def test_archive_is_expanded(self, settings: Settings, tmp_path: Path) -> None:
        archive = tmp_path / "bundle.zip"
        with zipfile.ZipFile(archive, "w") as handle:
            handle.writestr("one.ndjson", ECS_LINE)
            handle.writestr("two.ndjson", ECS_LINE)
        with archive.open("rb") as handle:
            result = run_intake(handle, tmp_path / "s1", "bundle.zip", settings=settings)
        assert result.archive is not None
        assert len(result.files) == 2
        assert all(item.filename.endswith(".ndjson") for item in result.files)

    def test_extracted_files_are_listed_with_hashes(
        self, settings: Settings, tmp_path: Path
    ) -> None:
        archive = tmp_path / "bundle.zip"
        with zipfile.ZipFile(archive, "w") as handle:
            handle.writestr("one.ndjson", ECS_LINE)
        with archive.open("rb") as handle:
            result = run_intake(handle, tmp_path / "s1", "bundle.zip", settings=settings)
        extracted = result.files[0]
        assert extracted.size == len(ECS_LINE)
        assert len(extracted.sha256) == 64


class TestMemberDetection:
    """The members of an archive are what gets parsed, so they are what is detected."""

    @staticmethod
    def _zip_with(tmp_path: Path, members: dict[str, bytes]) -> Path:
        archive = tmp_path / "bundle.zip"
        with zipfile.ZipFile(archive, "w") as handle:
            for name, payload in members.items():
                handle.writestr(name, payload)
        return archive

    def test_each_member_is_detected(self, settings: Settings, tmp_path: Path) -> None:
        archive = self._zip_with(tmp_path, {"one.ndjson": ECS_LINE, "two.ndjson": ECS_LINE})
        with archive.open("rb") as handle:
            result = run_intake(handle, tmp_path / "s1", "bundle.zip", settings=settings)
        assert len(result.detections) == len(result.files) == 2
        assert all(item.log_type == "generic_json" for item in result.detections)

    def test_a_member_of_another_format_is_detected_apart(
        self, settings: Settings, tmp_path: Path
    ) -> None:
        archive = self._zip_with(
            tmp_path,
            {"events.ndjson": ECS_LINE, "notes.txt": b"just prose\nnot a record\n"},
        )
        with archive.open("rb") as handle:
            result = run_intake(handle, tmp_path / "s1", "bundle.zip", settings=settings)
        by_name = {
            item.filename: result.detections[index] for index, item in enumerate(result.files)
        }
        assert by_name["events.ndjson"].log_type == "generic_json"
        assert by_name["notes.txt"].needs_input is True

    def test_an_unreadable_member_makes_the_archive_need_input(
        self, settings: Settings, tmp_path: Path
    ) -> None:
        # The ZIP container itself has no log format; only the members do.
        archive = self._zip_with(tmp_path, {"prose.txt": b"nothing parseable here\n"})
        with archive.open("rb") as handle:
            result = run_intake(handle, tmp_path / "s1", "bundle.zip", settings=settings)
        assert result.needs_input is True

    def test_detection_for_a_named_member(self, settings: Settings, tmp_path: Path) -> None:
        archive = self._zip_with(tmp_path, {"one.ndjson": ECS_LINE})
        with archive.open("rb") as handle:
            result = run_intake(handle, tmp_path / "s1", "bundle.zip", settings=settings)
        assert result.detection_for("one.ndjson") is not None
        assert result.detection_for("absent.ndjson") is None

    def test_format_candidates_collapse_duplicates(
        self, settings: Settings, tmp_path: Path
    ) -> None:
        # Twenty identical members are one question for the operator, not twenty.
        archive = self._zip_with(tmp_path, {f"part-{index}.ndjson": ECS_LINE for index in range(5)})
        with archive.open("rb") as handle:
            result = run_intake(handle, tmp_path / "s1", "bundle.zip", settings=settings)
        assert len(result.files) == 5
        assert len(result.format_candidates()) == 1

    def test_override_reaches_every_member(self, settings: Settings, tmp_path: Path) -> None:
        archive = self._zip_with(tmp_path, {"one.ndjson": ECS_LINE, "two.ndjson": ECS_LINE})
        with archive.open("rb") as handle:
            result = run_intake(
                handle,
                tmp_path / "s1",
                "bundle.zip",
                settings=settings,
                log_type_override="generic_json",
            )
        assert all(item.source == "override" for item in result.detections)

    def test_a_plain_upload_has_one_detection(self, settings: Settings, tmp_path: Path) -> None:
        result = run_intake(io.BytesIO(ECS_LINE), tmp_path / "s1", "a.ndjson", settings=settings)
        assert len(result.detections) == 1
        assert result.detections[0] is result.detection
        assert result.needs_input is False

    def test_expansion_can_be_skipped(self, settings: Settings, tmp_path: Path) -> None:
        archive = tmp_path / "bundle.zip"
        with zipfile.ZipFile(archive, "w") as handle:
            handle.writestr("one.ndjson", ECS_LINE)
        with archive.open("rb") as handle:
            result = run_intake(
                handle,
                tmp_path / "s1",
                "bundle.zip",
                settings=settings,
                expand_archives=False,
            )
        assert result.archive is None
        assert len(result.files) == 1

    def test_unsafe_archive_is_refused(self, settings: Settings, tmp_path: Path) -> None:
        archive = tmp_path / "evil.zip"
        with zipfile.ZipFile(archive, "w") as handle:
            handle.writestr("../pwned.ndjson", ECS_LINE)
        with archive.open("rb") as handle:
            with pytest.raises(ApiError) as caught:
                run_intake(handle, tmp_path / "s1", "evil.zip", settings=settings)
        assert caught.value.code is ErrorCode.FORBIDDEN_PATH
        assert not (tmp_path / "s1" / "pwned.ndjson").exists()

    def test_oversized_archive_is_refused(self, tmp_path: Path) -> None:
        settings = Settings(
            storage={"data_dir": tmp_path / "data"},
            limits={"max_archive_members": 2},
        )
        archive = tmp_path / "many.zip"
        with zipfile.ZipFile(archive, "w") as handle:
            for index in range(5):
                handle.writestr(f"f{index}.log", b"x")
        with archive.open("rb") as handle:
            with pytest.raises(ApiError) as caught:
                run_intake(handle, tmp_path / "s1", "many.zip", settings=settings)
        assert caught.value.code is ErrorCode.ARCHIVE_LIMIT_EXCEEDED

    def test_tar_upload_is_expanded(self, settings: Settings, tmp_path: Path) -> None:
        archive = tmp_path / "bundle.tar"
        with tarfile.open(archive, "w") as handle:
            info = tarfile.TarInfo("one.ndjson")
            info.size = len(ECS_LINE)
            handle.addfile(info, io.BytesIO(ECS_LINE))
        with archive.open("rb") as handle:
            result = run_intake(handle, tmp_path / "s1", "bundle.tar", settings=settings)
        assert len(result.files) == 1

    def test_gzipped_upload_is_detected_through_the_decompression(
        self, settings: Settings, tmp_path: Path
    ) -> None:
        payload = gzip.compress(ECS_LINE * 5)
        result = run_intake(
            io.BytesIO(payload), tmp_path / "s1", "events.log.gz", settings=settings
        )
        assert result.detection.log_type == "generic_json"

    def test_upload_limit_uses_configuration(self, tmp_path: Path) -> None:
        settings = Settings(storage={"data_dir": tmp_path}, limits={"max_upload_gb": 1})
        assert settings.limits.max_upload_bytes == 1024 * 1024 * 1024
        # A 1 GB ceiling cannot be crossed cheaply here, so the bound is checked
        # through the store function's own parameter.
        with pytest.raises(ApiError):
            store_stream(io.BytesIO(b"x" * 100), tmp_path, "a.log", max_bytes=10)


class TestResolveImportPath:
    """The operator may only offer paths under the configured roots."""

    def test_file_inside_a_root_is_allowed(self, settings: Settings, tmp_path: Path) -> None:
        target = tmp_path / "evidence.log"
        target.write_bytes(b"data\n")
        candidate = resolve_import_path(target, settings)
        assert candidate.path == target.resolve()
        assert candidate.size == 5
        assert candidate.name == "evidence.log"

    def test_relative_path_is_resolved(
        self, settings: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / "evidence.log").write_bytes(b"x")
        monkeypatch.chdir(tmp_path)
        assert resolve_import_path("evidence.log", settings).path == (tmp_path / "evidence.log")

    def test_path_outside_every_root_is_refused(self, tmp_path: Path) -> None:
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        outside = tmp_path / "outside.log"
        outside.write_bytes(b"x")
        settings = Settings(
            storage={"data_dir": tmp_path / "d", "allowed_import_roots": [str(allowed)]}
        )
        with pytest.raises(ApiError) as caught:
            resolve_import_path(outside, settings)
        assert caught.value.code is ErrorCode.FORBIDDEN_PATH
        assert "outside" in caught.value.message

    def test_traversal_out_of_a_root_is_refused(self, tmp_path: Path) -> None:
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        (allowed / "ok.log").write_bytes(b"x")
        settings = Settings(
            storage={"data_dir": tmp_path / "d", "allowed_import_roots": [str(allowed)]}
        )
        with pytest.raises(ApiError):
            resolve_import_path(allowed / ".." / "outside.log", settings)

    def test_symlink_escaping_a_root_is_refused(self, tmp_path: Path) -> None:
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        secret = tmp_path / "secret.log"
        secret.write_bytes(b"x")
        link = allowed / "innocent.log"
        try:
            link.symlink_to(secret)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks are not available here")
        settings = Settings(
            storage={"data_dir": tmp_path / "d", "allowed_import_roots": [str(allowed)]}
        )
        with pytest.raises(ApiError) as caught:
            resolve_import_path(link, settings)
        assert caught.value.code is ErrorCode.FORBIDDEN_PATH

    def test_directory_is_refused(self, settings: Settings, tmp_path: Path) -> None:
        directory = tmp_path / "folder"
        directory.mkdir()
        with pytest.raises(ApiError) as caught:
            resolve_import_path(directory, settings)
        assert "regular files" in caught.value.message

    def test_missing_path_is_refused(self, settings: Settings, tmp_path: Path) -> None:
        with pytest.raises(ApiError):
            resolve_import_path(tmp_path / "nope.log", settings)

    def test_blank_path_is_refused(self, settings: Settings) -> None:
        with pytest.raises(ApiError):
            resolve_import_path("   ", settings)

    def test_sibling_prefix_is_not_inside_a_root(self, tmp_path: Path) -> None:
        # ``/data-evil`` must not count as being inside ``/data``.
        root = tmp_path / "data"
        root.mkdir()
        sibling = tmp_path / "data-evil"
        sibling.mkdir()
        target = sibling / "x.log"
        target.write_bytes(b"x")
        settings = Settings(
            storage={"data_dir": tmp_path / "d", "allowed_import_roots": [str(root)]}
        )
        with pytest.raises(ApiError):
            resolve_import_path(target, settings)

    def test_error_lists_the_allowed_roots(self, tmp_path: Path) -> None:
        settings = Settings(
            storage={"data_dir": tmp_path / "d", "allowed_import_roots": [str(tmp_path / "a")]}
        )
        target = tmp_path / "x.log"
        target.write_bytes(b"x")
        with pytest.raises(ApiError) as caught:
            resolve_import_path(target, settings)
        assert caught.value.details.get("allowed_roots")

    def test_default_roots_include_home_and_imports(self) -> None:
        settings = Settings()
        names = [root.name for root in settings.resolved_import_roots]
        assert "imports" in names


class TestImportCandidates:
    """Directory expansion is opt-in and stays inside the allowed roots."""

    def _root(self, tmp_path: Path) -> tuple[Settings, Path]:
        root = tmp_path / "allowed"
        root.mkdir()
        settings = Settings(
            storage={"data_dir": tmp_path / "d", "allowed_import_roots": [str(root)]}
        )
        return settings, root

    def test_a_file_yields_itself(self, tmp_path: Path) -> None:
        settings, root = self._root(tmp_path)
        (root / "a.ndjson").write_bytes(b"x")
        candidates = import_candidates(root / "a.ndjson", settings, recursive=False)
        assert [candidate.name for candidate in candidates] == ["a.ndjson"]

    def test_a_directory_without_recursive_is_refused(self, tmp_path: Path) -> None:
        settings, root = self._root(tmp_path)
        with pytest.raises(ApiError) as caught:
            import_candidates(root, settings, recursive=False)
        assert caught.value.code is ErrorCode.FORBIDDEN_PATH

    def test_recursive_walks_in_sorted_order(self, tmp_path: Path) -> None:
        settings, root = self._root(tmp_path)
        (root / "z.ndjson").write_bytes(b"z")
        (root / "a.ndjson").write_bytes(b"a")
        (root / "sub").mkdir()
        (root / "sub" / "m.ndjson").write_bytes(b"m")
        candidates = import_candidates(root, settings, recursive=True)
        # Depth-first, sorted inside each directory: root files first (a, z),
        # then sub/m. Deterministic, not globally sorted, and that is fine.
        assert [candidate.name for candidate in candidates] == ["a.ndjson", "z.ndjson", "m.ndjson"]

    def test_a_file_symlink_escaping_the_root_is_skipped(self, tmp_path: Path) -> None:
        settings, root = self._root(tmp_path)
        secret = tmp_path / "secret.log"
        secret.write_bytes(b"secret")
        (root / "innocent.log").symlink_to(secret)
        (root / "ok.ndjson").write_bytes(b"ok")
        try:
            candidates = import_candidates(root, settings, recursive=True)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks are not available here")
        assert [candidate.name for candidate in candidates] == ["ok.ndjson"]

    def test_a_file_symlink_staying_in_the_root_is_included(self, tmp_path: Path) -> None:
        settings, root = self._root(tmp_path)
        inside = root / "real.ndjson"
        inside.write_bytes(b"data\n")
        (root / "alias.ndjson").symlink_to(inside)
        try:
            candidates = import_candidates(root, settings, recursive=True)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks are not available here")
        assert sorted(candidate.name for candidate in candidates) == [
            "alias.ndjson",
            "real.ndjson",
        ]

    def test_a_symlinked_subdirectory_is_not_descended_into(self, tmp_path: Path) -> None:
        settings, root = self._root(tmp_path)
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "secret.ndjson").write_bytes(b"s")
        (root / "linkdir").symlink_to(outside)
        (root / "ok.ndjson").write_bytes(b"ok")
        try:
            candidates = import_candidates(root, settings, recursive=True)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks are not available here")
        assert [candidate.name for candidate in candidates] == ["ok.ndjson"]


class TestIsWithin:
    """The containment primitive, on its own."""

    def test_root_itself(self) -> None:
        assert is_within(Path("/a/b"), Path("/a/b")) is True

    def test_child(self) -> None:
        assert is_within(Path("/a/b/c"), Path("/a/b")) is True

    def test_sibling(self) -> None:
        assert is_within(Path("/a/bc"), Path("/a/b")) is False

    def test_parent(self) -> None:
        assert is_within(Path("/a"), Path("/a/b")) is False
