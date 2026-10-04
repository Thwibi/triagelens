"""Hardened archive extraction (spec 03 section 5, spec 10 section 1).

An uploaded archive is hostile input. Everything here exists because of a
specific way archives have historically escaped a destination directory or
exhausted a disk:

- **Path escape.** A member called ``../../etc/cron.d/x`` or ``/etc/passwd`` or
  ``C:\\Windows\\x`` must never be written outside the destination, so every
  member name is parsed with POSIX rules and re-validated after joining.
- **Links.** A symlink or hardlink member can point anywhere, and a symlink to a
  directory followed by a further member turns into a write outside the
  destination. All links are refused rather than sanitized.
- **Special files.** Device nodes and FIFOs have no business in a log bundle and
  can block or confuse a reader, so only regular files and directories are
  accepted.
- **Bombs.** Declared sizes are checked before a single byte is written, and the
  running total is re-checked while streaming, because a member can lie about how
  much it will produce.

The destination is written by this module alone: archive libraries are asked for
bytes, never for a destination path, so no library's own path handling can be
tricked into writing somewhere unintended.
"""

from __future__ import annotations

import shutil
import stat
import tarfile
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from app.config import LimitsConfig
from app.errors import ApiError, ErrorCode

#: Archive extensions recognized without opening the file.
ARCHIVE_SUFFIXES: tuple[str, ...] = (
    ".zip",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz2",
    ".tar.xz",
    ".txz",
)

#: Read size while streaming a member out of an archive.
_COPY_CHUNK = 1 << 20

#: Shortest string that can carry a Windows drive letter, as in ``C:``.
_DRIVE_LETTER_LENGTH = 2

#: ``create_system`` value ZIP uses for Unix, where permission bits are meaningful.
_ZIP_UNIX_CREATE_SYSTEM = 3


@dataclass(frozen=True, slots=True)
class ArchiveLimits:
    """The bounds an extraction runs under, taken from configuration."""

    max_members: int
    max_total_bytes: int
    max_expansion_ratio: int
    max_depth: int

    @classmethod
    def from_config(cls, limits: LimitsConfig) -> ArchiveLimits:
        """Build from :class:`~app.config.LimitsConfig`."""
        return cls(
            max_members=limits.max_archive_members,
            max_total_bytes=limits.max_archive_total_bytes,
            max_expansion_ratio=limits.max_archive_expansion_ratio,
            max_depth=limits.max_archive_depth,
        )


@dataclass(slots=True)
class ExtractedFile:
    """One regular file written to disk."""

    member: str
    path: Path
    size: int


@dataclass(slots=True)
class ArchiveResult:
    """What an extraction produced."""

    root: Path
    files: list[ExtractedFile] = field(default_factory=list)
    total_bytes: int = 0

    @property
    def paths(self) -> list[Path]:
        """Just the paths, for handing to detection."""
        return [item.path for item in self.files]


def is_archive(path: Path) -> bool:
    """True when the name suggests an archive worth expanding."""
    name = path.name.lower()
    return any(name.endswith(suffix) for suffix in ARCHIVE_SUFFIXES)


def _reject(message: str, **details: object) -> ApiError:
    """A limit or safety violation, as the spec's stable error code."""
    return ApiError(ErrorCode.ARCHIVE_LIMIT_EXCEEDED, message, **details)


def _forbidden(message: str, **details: object) -> ApiError:
    """A path or member that must never be extracted."""
    return ApiError(ErrorCode.FORBIDDEN_PATH, message, **details)


def safe_member_name(name: str) -> PurePosixPath:
    """Validate one member name and return it as a relative POSIX path.

    Raises:
        ApiError: ``FORBIDDEN_PATH`` for anything that could escape the
            destination: an absolute path, a drive letter, a UNC path, a ``..``
            segment, or an empty name.
    """
    if not name or name.strip() in {"", ".", "./"}:
        raise _forbidden("archive member has an empty name", member=name)

    # ZIP and TAR both store names with forward slashes, but a crafted member can
    # carry backslashes, which Windows would read as separators.
    candidate = name.replace("\\", "/")

    if candidate.startswith("/"):
        raise _forbidden("archive member has an absolute path", member=name)
    if candidate.startswith("//"):
        raise _forbidden("archive member has a UNC path", member=name)
    if len(candidate) >= _DRIVE_LETTER_LENGTH and candidate[1] == ":":
        raise _forbidden("archive member has a drive letter", member=name)

    parts: list[str] = []
    for segment in PurePosixPath(candidate).parts:
        if segment in {"", "."}:
            continue
        if segment == "..":
            raise _forbidden("archive member escapes the destination", member=name)
        if "\x00" in segment:
            raise _forbidden("archive member name contains a NUL byte", member=name)
        parts.append(segment)
    if not parts:
        raise _forbidden("archive member has an empty name", member=name)
    return PurePosixPath(*parts)


def _depth(name: PurePosixPath) -> int:
    """How many directories deep a member sits."""
    return len(name.parts) - 1


def _check_depth(relative: PurePosixPath, limits: ArchiveLimits) -> None:
    """Refuse nesting deeper than configured."""
    if _depth(relative) > limits.max_depth:
        raise _reject(
            f"archive nesting deeper than {limits.max_depth}",
            member=str(relative),
            max_depth=limits.max_depth,
        )


def _resolve_destination(root: Path, relative: PurePosixPath) -> Path:
    """Join a validated member name to the destination and prove containment.

    The name has already been validated, and this is the second, independent
    check: the resolved path must still be inside ``root`` even after symlinks
    that already existed in the destination are taken into account.
    """
    target = (root / Path(*relative.parts)).resolve()
    resolved_root = root.resolve()
    if target != resolved_root and resolved_root not in target.parents:
        raise _forbidden("archive member escapes the destination", member=str(relative))
    return target


def _check_declared_sizes(count: int, total: int, archive_size: int, limits: ArchiveLimits) -> None:
    """Refuse an archive that is too big or too compressed before writing.

    Args:
        count: Number of members.
        total: Sum of declared uncompressed sizes.
        archive_size: Size of the archive file on disk.
        limits: Bounds to enforce.
    """
    if count > limits.max_members:
        raise _reject(
            f"archive has more than {limits.max_members} members",
            members=count,
            max_members=limits.max_members,
        )
    if total > limits.max_total_bytes:
        raise _reject(
            "archive expands beyond the configured total size",
            declared_bytes=total,
            max_total_bytes=limits.max_total_bytes,
        )
    if archive_size > 0 and total / archive_size > limits.max_expansion_ratio:
        raise _reject(
            f"archive expansion ratio exceeds {limits.max_expansion_ratio}",
            declared_bytes=total,
            archive_bytes=archive_size,
            max_expansion_ratio=limits.max_expansion_ratio,
        )


def _write_member(
    root: Path,
    relative: PurePosixPath,
    stream: Iterator[bytes],
    budget: _Budget,
) -> ExtractedFile:
    """Stream one member to disk, refusing to exceed the running total."""
    target = _resolve_destination(root, relative)
    target.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with target.open("wb") as handle:
        for chunk in stream:
            written += len(chunk)
            budget.consume(len(chunk))
            handle.write(chunk)
    return ExtractedFile(member=str(relative), path=target, size=written)


class _Budget:
    """Running total of bytes written, checked against the configured limit.

    Declared sizes are checked first, but a member that under-reports its length
    would otherwise be able to exceed the limit while streaming, so the total is
    enforced again here.
    """

    __slots__ = ("_limit", "used")

    def __init__(self, limit: int) -> None:
        self._limit = limit
        self.used = 0

    def consume(self, count: int) -> None:
        """Add to the total, refusing when it would pass the limit."""
        if self.used + count > self._limit:
            raise _reject(
                "archive expands beyond the configured total size",
                max_total_bytes=self._limit,
            )
        self.used += count


def _tar_type_name(member_type: bytes) -> str:
    """A readable name for a TAR member type, for the refusal message."""
    names = {
        tarfile.SYMTYPE: "symlink",
        tarfile.LNKTYPE: "hardlink",
        tarfile.CHRTYPE: "character device",
        tarfile.BLKTYPE: "block device",
        tarfile.FIFOTYPE: "fifo",
        tarfile.CONTTYPE: "contiguous file",
    }
    return names.get(member_type, "special file")


def _is_zip_symlink(info: zipfile.ZipInfo) -> bool:
    """True when a ZIP entry is a symlink rather than a plain file.

    ZIP has no symlink type of its own; Unix permissions live in the high bits of
    ``external_attr``, so a member whose mode has ``S_IFLNK`` is a link.
    """
    if info.create_system != _ZIP_UNIX_CREATE_SYSTEM:
        return False
    mode = info.external_attr >> 16
    return bool(mode) and stat.S_ISLNK(mode)


def _is_encrypted(info: zipfile.ZipInfo) -> bool:
    """True when a ZIP entry is password-protected."""
    return bool(info.flag_bits & 0x1)


def extract_zip(path: Path, destination: Path, limits: ArchiveLimits) -> ArchiveResult:
    """Extract a ZIP archive safely."""
    result = ArchiveResult(root=destination)
    archive_size = path.stat().st_size
    with zipfile.ZipFile(path) as archive:
        infos = [info for info in archive.infolist() if not info.is_dir()]
        _check_declared_sizes(
            len(infos),
            sum(max(0, info.file_size) for info in infos),
            archive_size,
            limits,
        )
        budget = _Budget(limits.max_total_bytes)
        for info in infos:
            relative = safe_member_name(info.filename)
            _check_depth(relative, limits)
            if _is_zip_symlink(info):
                raise _forbidden("archive member is a symlink", member=info.filename)
            if _is_encrypted(info):
                raise _forbidden("archive member is password-protected", member=info.filename)
            with archive.open(info) as stream:
                result.files.append(_write_member(destination, relative, stream, budget))
    result.total_bytes = budget.used
    return result


def extract_tar(path: Path, destination: Path, limits: ArchiveLimits) -> ArchiveResult:
    """Extract a TAR archive safely, in any compression it declares."""
    result = ArchiveResult(root=destination)
    archive_size = path.stat().st_size
    budget = _Budget(limits.max_total_bytes)
    with tarfile.open(path, "r:*") as archive:
        members = archive.getmembers()
        for member in members:
            # Directories are structure and are recreated as needed. Anything
            # else - symlink, hardlink, device, fifo, socket - is refused rather
            # than skipped: a member that is silently dropped is evidence missing
            # from the case, which for a triage tool is worse than a refusal.
            if member.isdir():
                continue
            if not member.isfile():
                kind = _tar_type_name(member.type)
                raise _forbidden(
                    f"archive member is a {kind}, which is not extracted",
                    member=member.name,
                    type=kind,
                )
        files = [member for member in members if member.isfile()]
        _check_declared_sizes(
            len(members),
            sum(max(0, member.size) for member in files),
            archive_size,
            limits,
        )
        for member in files:
            relative = safe_member_name(member.name)
            _check_depth(relative, limits)
            stream = archive.extractfile(member)
            if stream is None:
                raise _forbidden("archive member could not be read", member=member.name)
            with stream:
                result.files.append(_write_member(destination, relative, stream, budget))
    result.total_bytes = budget.used
    return result


def extract_archive(path: Path, destination: Path, limits: ArchiveLimits) -> ArchiveResult:
    """Extract ``path`` into ``destination``, refusing anything unsafe.

    Args:
        path: The archive on disk.
        destination: Directory to extract into; created if absent. Nothing is ever
            written outside it.
        limits: Bounds from configuration.

    Returns:
        Every regular file written, with sizes.

    Raises:
        ApiError: ``UNSUPPORTED_FORMAT`` when the file is not a readable ZIP or
            TAR, ``FORBIDDEN_PATH`` for an unsafe member, and
            ``ARCHIVE_LIMIT_EXCEEDED`` for a bomb or an oversized archive.
    """
    destination.mkdir(parents=True, exist_ok=True)
    try:
        if zipfile.is_zipfile(path):
            return extract_zip(path, destination, limits)
        if tarfile.is_tarfile(path):
            return extract_tar(path, destination, limits)
    except ApiError:
        raise
    except (tarfile.TarError, zipfile.BadZipFile, EOFError, OSError) as error:
        raise ApiError(
            ErrorCode.UNSUPPORTED_FORMAT,
            "archive could not be read",
            detail=type(error).__name__,
        ) from None
    raise ApiError(
        ErrorCode.UNSUPPORTED_FORMAT,
        "file is not a readable ZIP or TAR archive",
    )


def make_read_only(root: Path) -> None:
    """Remove write permission from everything under ``root``.

    Stored evidence is read-only so that nothing downstream - including a future
    rule engine or report writer - can alter what was ingested. On Windows this
    clears the read-only attribute; on POSIX it clears the write bits.
    """
    for path in [root, *root.rglob("*")]:
        try:
            mode = path.stat().st_mode
            path.chmod(mode & ~0o222)
        except OSError:
            # A file that vanished or is held open elsewhere must not stop the
            # rest of the tree from being protected.
            continue


def disk_free_bytes(path: Path) -> int:
    """Free space on the filesystem holding ``path``.

    Used before extraction to refuse an archive that cannot fit. ``statvfs`` is
    not available on Windows, so :func:`shutil.disk_usage` is the portable path.
    """
    return shutil.disk_usage(path).free


__all__ = [
    "ARCHIVE_SUFFIXES",
    "ArchiveLimits",
    "ArchiveResult",
    "ExtractedFile",
    "disk_free_bytes",
    "extract_archive",
    "is_archive",
    "make_read_only",
    "safe_member_name",
]
