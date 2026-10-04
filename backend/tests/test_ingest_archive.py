"""Archive extraction hardening (spec 03 section 5, spec 09 P-09, P-10, P-11).

These tests are the point of the module: each one is a way an archive has escaped
a destination directory or filled a disk in the wild.
"""

from __future__ import annotations

import io
import os
import stat
import tarfile
import zipfile
from pathlib import Path
from typing import IO, Literal

import pytest

from app.config import LimitsConfig
from app.errors import ApiError, ErrorCode
from app.ingest.archive import (
    ArchiveLimits,
    _is_encrypted,
    _is_zip_symlink,
    extract_archive,
    is_archive,
    make_read_only,
    safe_member_name,
)

#: Small but permissive enough that ordinary archives pass.
LIMITS = ArchiveLimits(
    max_members=10,
    max_total_bytes=1_000_000,
    max_expansion_ratio=100,
    max_depth=3,
)


def make_zip(path: Path, members: dict[str, bytes], *, symlinks: tuple[str, ...] = ()) -> Path:
    """A ZIP whose entries are given explicitly, including hostile names."""
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in members.items():
            info = zipfile.ZipInfo(name)
            if name in symlinks:
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, data)
    return path


TarWriteMode = Literal["w", "w:gz", "w:bz2", "w:xz"]


def make_tar(path: Path, members: dict[str, bytes], *, mode: TarWriteMode = "w") -> Path:
    """A TAR with the given members, optionally compressed."""
    with tarfile.open(path, mode) as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io_bytes(data))
    return path


def io_bytes(data: bytes) -> IO[bytes]:
    """A file-like object for ``TarFile.addfile``."""
    return io.BytesIO(data)


def test_limits_come_from_config() -> None:
    limits = ArchiveLimits.from_config(LimitsConfig(max_archive_members=7))
    assert limits.max_members == 7
    assert limits.max_depth == LimitsConfig().max_archive_depth


class TestIsArchive:
    """Only names worth opening are treated as archives."""

    @pytest.mark.parametrize(
        "name",
        ["a.zip", "a.tar", "a.tar.gz", "a.tgz", "a.tar.bz2", "a.tar.xz", "A.ZIP"],
    )
    def test_recognized(self, name: str) -> None:
        assert is_archive(Path(name)) is True

    @pytest.mark.parametrize("name", ["a.log", "a.ndjson", "a.gz", "zip", "a.tar.zst"])
    def test_not_recognized(self, name: str) -> None:
        assert is_archive(Path(name)) is False


class TestMemberNames:
    """Every escape vector is refused by name, before any write."""

    @pytest.mark.parametrize(
        "name",
        [
            "../escape.txt",
            "a/../../escape.txt",
            "/etc/passwd",
            "//server/share/x",
            "C:\\Windows\\system32\\x",
            "C:evil.txt",
            "..\\escape.txt",
        ],
    )
    def test_escaping_names_are_refused(self, name: str) -> None:
        with pytest.raises(ApiError) as caught:
            safe_member_name(name)
        assert caught.value.code is ErrorCode.FORBIDDEN_PATH

    def test_nul_byte_is_refused(self) -> None:
        with pytest.raises(ApiError):
            safe_member_name("a\x00b.txt")

    @pytest.mark.parametrize("name", ["", "   ", ".", "./"])
    def test_empty_names_are_refused(self, name: str) -> None:
        with pytest.raises(ApiError):
            safe_member_name(name)

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("a.txt", ("a.txt",)),
            ("./a.txt", ("a.txt",)),
            ("a/b/c.txt", ("a", "b", "c.txt")),
            ("a//b.txt", ("a", "b.txt")),
            ("a/./b.txt", ("a", "b.txt")),
            ("dir\\file.txt", ("dir", "file.txt")),
        ],
    )
    def test_ordinary_names_are_normalized(self, name: str, expected: tuple[str, ...]) -> None:
        assert safe_member_name(name).parts == expected


class TestZipExtraction:
    """The ordinary path still has to work."""

    def test_extracts_files(self, tmp_path: Path) -> None:
        archive = make_zip(tmp_path / "a.zip", {"one.log": b"one\n", "sub/two.log": b"two\n"})
        result = extract_archive(archive, tmp_path / "out", LIMITS)
        assert len(result.files) == 2
        assert (tmp_path / "out" / "one.log").read_bytes() == b"one\n"
        assert (tmp_path / "out" / "sub" / "two.log").read_bytes() == b"two\n"

    def test_reports_member_names_and_sizes(self, tmp_path: Path) -> None:
        archive = make_zip(tmp_path / "a.zip", {"one.log": b"12345"})
        result = extract_archive(archive, tmp_path / "out", LIMITS)
        assert result.files[0].member == "one.log"
        assert result.files[0].size == 5
        assert result.total_bytes == 5

    def test_zip_slip_writes_nothing_outside(self, tmp_path: Path) -> None:
        archive = make_zip(tmp_path / "evil.zip", {"../pwned.txt": b"x"})
        with pytest.raises(ApiError):
            extract_archive(archive, tmp_path / "out", LIMITS)
        assert not (tmp_path / "pwned.txt").exists()

    def test_absolute_member_is_refused(self, tmp_path: Path) -> None:
        archive = make_zip(tmp_path / "abs.zip", {"/tmp/pwned.txt": b"x"})
        with pytest.raises(ApiError) as caught:
            extract_archive(archive, tmp_path / "out", LIMITS)
        assert caught.value.code is ErrorCode.FORBIDDEN_PATH

    def test_symlink_member_is_refused(self, tmp_path: Path) -> None:
        archive = make_zip(tmp_path / "link.zip", {"link": b"/etc/passwd"}, symlinks=("link",))
        with pytest.raises(ApiError) as caught:
            extract_archive(archive, tmp_path / "out", LIMITS)
        assert "symlink" in caught.value.message
        assert not (tmp_path / "out" / "link").exists()

    def test_encrypted_member_is_detected(self) -> None:
        # A real password-protected ZIP cannot be forged with zipfile, which
        # rewrites flag_bits on write, so the detection is unit-tested directly.
        info = zipfile.ZipInfo("secret.log")
        info.flag_bits = 0x1
        assert _is_encrypted(info) is True
        assert _is_encrypted(zipfile.ZipInfo("plain.log")) is False

    def test_password_protected_archive_is_refused_when_present(self, tmp_path: Path) -> None:
        pytest.importorskip("pyzipper")
        import pyzipper  # type: ignore[import-not-found]

        archive = tmp_path / "pw.zip"
        with pyzipper.AESZipFile(archive, "w", encryption=pyzipper.WZ_AES) as handle:
            handle.setpassword(b"secret")
            handle.writestr("a.log", b"data")
        with pytest.raises(ApiError) as caught:
            extract_archive(archive, tmp_path / "out", LIMITS)
        assert "password" in caught.value.message

    def test_zip_symlink_detection_is_unit_tested(self) -> None:
        info = zipfile.ZipInfo("link")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        assert _is_zip_symlink(info) is True
        assert _is_zip_symlink(zipfile.ZipInfo("plain.log")) is False


class TestTarExtraction:
    """TAR carries real file types, which is where links come from."""

    def test_extracts_files(self, tmp_path: Path) -> None:
        archive = make_tar(tmp_path / "a.tar", {"one.log": b"one\n"})
        result = extract_archive(archive, tmp_path / "out", LIMITS)
        assert (tmp_path / "out" / "one.log").read_bytes() == b"one\n"
        assert len(result.files) == 1

    @pytest.mark.parametrize(
        ("mode", "name"),
        [
            pytest.param("w:gz", "a.tar.gz", id="gzip"),
            pytest.param("w:bz2", "a.tar.bz2", id="bzip2"),
            pytest.param("w:xz", "a.tar.xz", id="xz"),
        ],
    )
    def test_compressed_tar_variants(self, tmp_path: Path, mode: TarWriteMode, name: str) -> None:
        archive = make_tar(tmp_path / name, {"one.log": b"one\n"}, mode=mode)
        assert extract_archive(archive, tmp_path / "out", LIMITS).files[0].size == 4

    def test_directory_members_are_skipped(self, tmp_path: Path) -> None:
        archive = tmp_path / "dirs.tar"
        with tarfile.open(archive, "w") as handle:
            info = tarfile.TarInfo("sub")
            info.type = tarfile.DIRTYPE
            handle.addfile(info)
            payload = b"x"
            member = tarfile.TarInfo("sub/real.log")
            member.size = len(payload)
            handle.addfile(member, io.BytesIO(payload))
        assert len(extract_archive(archive, tmp_path / "out", LIMITS).files) == 1

    def test_symlink_member_is_refused(self, tmp_path: Path) -> None:
        archive = tmp_path / "link.tar"
        with tarfile.open(archive, "w") as handle:
            info = tarfile.TarInfo("link")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            handle.addfile(info)
        with pytest.raises(ApiError) as caught:
            extract_archive(archive, tmp_path / "out", LIMITS)
        assert "symlink" in caught.value.message
        assert not (tmp_path / "out" / "link").exists()

    def test_hardlink_member_is_refused(self, tmp_path: Path) -> None:
        archive = tmp_path / "hard.tar"
        with tarfile.open(archive, "w") as handle:
            info = tarfile.TarInfo("real.log")
            info.type = tarfile.LNKTYPE
            info.linkname = "/etc/passwd"
            handle.addfile(info)
        with pytest.raises(ApiError) as caught:
            extract_archive(archive, tmp_path / "out", LIMITS)
        assert "hardlink" in caught.value.message

    def test_traversal_member_is_refused(self, tmp_path: Path) -> None:
        archive = make_tar(tmp_path / "up.tar", {"../pwned.txt": b"x"})
        with pytest.raises(ApiError):
            extract_archive(archive, tmp_path / "out", LIMITS)
        assert not (tmp_path / "pwned.txt").exists()

    def test_fifo_member_is_refused_rather_than_silently_dropped(self, tmp_path: Path) -> None:
        archive = tmp_path / "fifo.tar"
        with tarfile.open(archive, "w") as handle:
            info = tarfile.TarInfo("pipe")
            info.type = tarfile.FIFOTYPE
            handle.addfile(info)
        with pytest.raises(ApiError) as caught:
            extract_archive(archive, tmp_path / "out", LIMITS)
        assert "fifo" in caught.value.message

    def test_device_member_is_refused_rather_than_silently_dropped(self, tmp_path: Path) -> None:
        archive = tmp_path / "dev.tar"
        with tarfile.open(archive, "w") as handle:
            info = tarfile.TarInfo("null")
            info.type = tarfile.CHRTYPE
            info.devmajor, info.devminor = 1, 3
            handle.addfile(info)
        with pytest.raises(ApiError) as caught:
            extract_archive(archive, tmp_path / "out", LIMITS)
        assert "character device" in caught.value.message

    def test_a_refused_link_stops_earlier_files_from_being_written(self, tmp_path: Path) -> None:
        archive = tmp_path / "mixed.tar"
        with tarfile.open(archive, "w") as handle:
            payload = b"good"
            member = tarfile.TarInfo("first.log")
            member.size = len(payload)
            handle.addfile(member, io.BytesIO(payload))
            link = tarfile.TarInfo("second-link")
            link.type = tarfile.SYMTYPE
            link.linkname = "/etc/passwd"
            handle.addfile(link)
        with pytest.raises(ApiError):
            extract_archive(archive, tmp_path / "out", LIMITS)
        # Refusal happens before any member is written, so the case never holds a
        # partial archive that looks like a complete one.
        assert not (tmp_path / "out" / "first.log").exists()


class TestLimits:
    """Bounds are checked before writing, not after."""

    def test_too_many_members(self, tmp_path: Path) -> None:
        members = {f"f{n}.log": b"x" for n in range(LIMITS.max_members + 1)}
        archive = make_zip(tmp_path / "many.zip", members)
        with pytest.raises(ApiError) as caught:
            extract_archive(archive, tmp_path / "out", LIMITS)
        assert caught.value.code is ErrorCode.ARCHIVE_LIMIT_EXCEEDED
        assert "members" in caught.value.message

    def test_declared_total_over_limit(self, tmp_path: Path) -> None:
        limits = ArchiveLimits(
            max_members=10, max_total_bytes=100, max_expansion_ratio=1000, max_depth=3
        )
        archive = make_zip(tmp_path / "big.zip", {"big.log": b"x" * 500})
        with pytest.raises(ApiError) as caught:
            extract_archive(archive, tmp_path / "out", limits)
        assert "expands beyond" in caught.value.message
        assert not (tmp_path / "out" / "big.log").exists()

    def test_expansion_ratio_bomb(self, tmp_path: Path) -> None:
        # 1 MB of zeroes compresses to a few hundred bytes: a ratio far past 100.
        limits = ArchiveLimits(
            max_members=10, max_total_bytes=100_000_000, max_expansion_ratio=10, max_depth=3
        )
        archive = tmp_path / "bomb.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as handle:
            handle.writestr("bomb.log", b"\x00" * 1_000_000)
        assert archive.stat().st_size < 10_000
        with pytest.raises(ApiError) as caught:
            extract_archive(archive, tmp_path / "out", limits)
        assert "expansion ratio" in caught.value.message

    def test_nesting_deeper_than_allowed(self, tmp_path: Path) -> None:
        archive = make_zip(tmp_path / "deep.zip", {"a/b/c/d/e.log": b"x"})
        with pytest.raises(ApiError) as caught:
            extract_archive(archive, tmp_path / "out", LIMITS)
        assert "nesting" in caught.value.message

    def test_nesting_within_limit_is_allowed(self, tmp_path: Path) -> None:
        archive = make_zip(tmp_path / "ok.zip", {"a/b/c.log": b"x"})
        assert extract_archive(archive, tmp_path / "out", LIMITS).files[0].size == 1

    def test_streamed_total_is_enforced_even_if_declared_is_small(self, tmp_path: Path) -> None:
        # A member that lies about its size: the running budget must catch it.
        limits = ArchiveLimits(
            max_members=10, max_total_bytes=200, max_expansion_ratio=1_000_000, max_depth=3
        )
        archive = tmp_path / "liar.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_STORED) as handle:
            info = zipfile.ZipInfo("liar.log")
            info.file_size = 1
            handle.writestr(info, b"x" * 5000)
        with pytest.raises(ApiError):
            extract_archive(archive, tmp_path / "out", limits)


class TestUnsupportedInput:
    """A file that is not an archive is a format error, not a crash."""

    def test_plain_file(self, tmp_path: Path) -> None:
        path = tmp_path / "a.log"
        path.write_bytes(b"not an archive")
        with pytest.raises(ApiError) as caught:
            extract_archive(path, tmp_path / "out", LIMITS)
        assert caught.value.code is ErrorCode.UNSUPPORTED_FORMAT

    def test_truncated_zip(self, tmp_path: Path) -> None:
        archive = make_zip(tmp_path / "a.zip", {"a.log": b"data"})
        archive.write_bytes(archive.read_bytes()[:20])
        with pytest.raises(ApiError) as caught:
            extract_archive(archive, tmp_path / "out", LIMITS)
        assert caught.value.code is ErrorCode.UNSUPPORTED_FORMAT

    def test_empty_file(self, tmp_path: Path) -> None:
        path = tmp_path / "empty.zip"
        path.write_bytes(b"")
        with pytest.raises(ApiError):
            extract_archive(path, tmp_path / "out", LIMITS)

    def test_destination_is_created(self, tmp_path: Path) -> None:
        archive = make_zip(tmp_path / "a.zip", {"a.log": b"x"})
        target = tmp_path / "deep" / "out"
        extract_archive(archive, target, LIMITS)
        assert target.is_dir()


class TestReadOnly:
    """Stored evidence is protected from later stages."""

    def test_files_become_read_only(self, tmp_path: Path) -> None:
        archive = make_zip(tmp_path / "a.zip", {"a.log": b"x", "sub/b.log": b"y"})
        destination = tmp_path / "out"
        extract_archive(archive, destination, LIMITS)
        make_read_only(destination)
        assert not (destination / "a.log").stat().st_mode & stat.S_IWRITE
        assert not (destination / "sub" / "b.log").stat().st_mode & stat.S_IWRITE

    def test_missing_file_does_not_stop_the_walk(self, tmp_path: Path) -> None:
        root = tmp_path / "out"
        root.mkdir()
        (root / "a.log").write_bytes(b"x")
        make_read_only(root)
        assert (root / "a.log").exists()

    @pytest.mark.skipif(os.name != "nt", reason="Windows read-only attribute")
    def test_windows_read_only_attribute_is_set(self, tmp_path: Path) -> None:
        path = tmp_path / "a.log"
        path.write_bytes(b"x")
        make_read_only(tmp_path)
        assert path.stat().st_file_attributes & stat.FILE_ATTRIBUTE_READONLY
