"""Upload intake (spec 03 section 5, spec 09 P-08).

Three things happen here, in this order, and the order matters:

1. **Store.** The upload is streamed to disk while being hashed and measured. A
   client-supplied ``Content-Length`` is never trusted, so the size cap is
   enforced by counting bytes as they arrive and the partial file is removed when
   the cap is passed.
2. **Expand.** An archive is extracted under the hardened rules in
   :mod:`app.ingest.archive`.
3. **Detect.** Every stored file is run through detection, so the caller learns
   the format or gets a ``needs_input`` answer with candidates.

The filename a client sends is treated as a label, never as a path. It is
reduced to a safe basename before it is used to build any filesystem path.
"""

from __future__ import annotations

import contextlib
import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from app.config import Settings
from app.errors import ApiError, ErrorCode
from app.ingest.archive import (
    ArchiveLimits,
    ArchiveResult,
    extract_archive,
    is_archive,
    make_read_only,
)
from app.ingest.detect import DetectionResult, detect

#: Read size while streaming an upload to disk.
CHUNK_BYTES = 1 << 20

#: Longest stored filename; longer names are truncated rather than refused, since
#: the original is preserved in the database regardless.
MAX_FILENAME_LENGTH = 180

#: Longest extension worth preserving when a long name is truncated. Anything
#: longer is not an extension at all but part of the stem.
_MAX_EXTENSION_LENGTH = 16

#: Used when a client sends something that is not a usable name.
FALLBACK_FILENAME = "upload.bin"

#: Characters allowed in a stored filename. Everything else becomes ``_``, which
#: removes path separators, drive letters, control characters and shell metacharacters.
_UNSAFE_NAME_CHARS = re.compile(r"[^A-Za-z0-9._-]+")


@dataclass(slots=True)
class StoredFile:
    """One file written under the case's storage directory."""

    path: Path
    #: The name as the client sent it, kept for display and for the source row.
    filename: str
    size: int
    sha256: str

    @property
    def name(self) -> str:
        """The name on disk."""
        return self.path.name


@dataclass(slots=True)
class IntakeResult:
    """What intake produced for one upload."""

    stored: StoredFile
    detection: DetectionResult
    #: Populated when the upload was an archive.
    archive: ArchiveResult | None = None
    #: Every stored file, including files extracted from an archive.
    files: list[StoredFile] = field(default_factory=list)
    #: A detection result per entry of :attr:`files`, in the same order.
    detections: list[DetectionResult] = field(default_factory=list)

    @property
    def needs_input(self) -> bool:
        """True when the operator must choose a format.

        For an archive this asks about the members rather than the container: a
        ZIP of well-formed syslog files needs no operator input even though the
        ZIP itself has no log format at all.
        """
        return any(result.needs_input for result in self.detections) or self.detection.needs_input

    def detection_for(self, member: str) -> DetectionResult | None:
        """Detection for the stored file whose name is ``member``, if any."""
        for stored, result in zip(self.files, self.detections, strict=True):
            if stored.filename == member:
                return result
        return None

    def format_candidates(self) -> list[DetectionResult]:
        """Distinct results worth showing an operator, archives collapsed."""
        seen: dict[tuple[str, str], DetectionResult] = {}
        for result in self.detections:
            seen.setdefault((result.log_type or "", result.reason), result)
        return list(seen.values())


def safe_filename(name: str) -> str:
    """Reduce a client-supplied filename to something safe to write.

    Directory components are discarded, unsafe characters replaced, a leading dot
    or dash removed (so a stored name can never be mistaken for a hidden file or
    an option), and the result length-bounded.

    Raises:
        ApiError: ``FORBIDDEN_PATH`` when nothing usable survives.
    """
    candidate = name.replace("\\", "/").split("/")[-1].strip()
    cleaned = _UNSAFE_NAME_CHARS.sub("_", candidate).strip("._-")
    if not cleaned:
        raise ApiError(
            ErrorCode.FORBIDDEN_PATH,
            "uploaded filename contains no usable characters",
            filename=name,
        )
    if len(cleaned) > MAX_FILENAME_LENGTH:
        # Keep the extension, since detection and the operator both use it.
        stem, dot, extension = cleaned.rpartition(".")
        if dot and len(extension) <= _MAX_EXTENSION_LENGTH:
            keep = MAX_FILENAME_LENGTH - len(extension) - 1
            cleaned = f"{stem[:keep]}.{extension}"
        else:
            cleaned = cleaned[:MAX_FILENAME_LENGTH]
    return cleaned


def store_stream(
    stream: Iterable[bytes],
    destination_dir: Path,
    filename: str,
    *,
    max_bytes: int,
) -> StoredFile:
    """Stream an upload into ``destination_dir``, hashing and bounding it.

    The size cap is applied to bytes actually received, not to any declared
    length, so a client cannot understate it. On overflow the partial file is
    removed before raising, so a rejected upload leaves nothing behind.

    Raises:
        ApiError: ``UPLOAD_TOO_LARGE`` when more than ``max_bytes`` arrive.
    """
    stored_name = safe_filename(filename)
    destination_dir.mkdir(parents=True, exist_ok=True)
    target = destination_dir / stored_name

    try:
        with target.open("wb") as handle:
            total, digest = _write_bounded(stream, handle, max_bytes)
    except BaseException:
        # Any failure, including a client disconnect, must not leave a partial
        # file that a later run would treat as complete evidence.
        target.unlink(missing_ok=True)
        raise

    if total == 0:
        target.unlink(missing_ok=True)
        raise ApiError(
            ErrorCode.UNSUPPORTED_FORMAT,
            "uploaded file is empty",
            filename=filename,
        )

    return StoredFile(path=target, filename=filename, size=total, sha256=digest)


def _write_bounded(stream: Iterable[bytes], handle: object, max_bytes: int) -> tuple[int, str]:
    """Copy ``stream`` into ``handle``, hashing it and stopping at ``max_bytes``.

    Returns the number of bytes written and their SHA-256 hex digest.

    Raises:
        ApiError: ``UPLOAD_TOO_LARGE`` as soon as more than ``max_bytes`` arrive.
    """
    digest = hashlib.sha256()
    total = 0
    for chunk in stream:
        total += len(chunk)
        if total > max_bytes:
            raise ApiError(
                ErrorCode.UPLOAD_TOO_LARGE,
                f"upload exceeds the {max_bytes} byte limit",
                max_bytes=max_bytes,
            )
        digest.update(chunk)
        handle.write(chunk)  # type: ignore[attr-defined]
    return total, digest.hexdigest()


def store_file(
    path: Path,
    destination_dir: Path,
    *,
    max_bytes: int,
    filename: str | None = None,
) -> StoredFile:
    """Copy an existing file into storage under the same rules as an upload."""
    with path.open("rb") as handle:
        return store_stream(handle, destination_dir, filename or path.name, max_bytes=max_bytes)


def _extract(stored: StoredFile, destination_dir: Path, limits: ArchiveLimits) -> ArchiveResult:
    """Expand an archive next to itself, refusing anything unsafe."""
    return extract_archive(stored.path, destination_dir / f"{stored.name}.extracted", limits)


def intake_stream(
    stream: Iterable[bytes],
    destination_dir: Path,
    filename: str,
    *,
    settings: Settings,
    log_type_override: str | None = None,
    expand_archives: bool = True,
) -> IntakeResult:
    """Store an upload, expand it if it is an archive, and detect every file.

    Args:
        stream: The request body, as an iterable of byte chunks.
        destination_dir: Per-source directory under the case's storage root.
        filename: The client-supplied name.
        settings: Supplies the size limits and detection configuration.
        log_type_override: A format the operator chose, which skips detection.
        expand_archives: Set false to store an archive without expanding it.

    Returns:
        The stored file, its detection result, and any extracted files.

    Raises:
        ApiError: ``UPLOAD_TOO_LARGE``, ``UNSUPPORTED_FORMAT``,
            ``ARCHIVE_LIMIT_EXCEEDED`` or ``FORBIDDEN_PATH``.
    """
    limits = settings.limits
    stored = store_stream(stream, destination_dir, filename, max_bytes=limits.max_upload_bytes)

    archive_result: ArchiveResult | None = None
    files = [stored]
    if expand_archives and is_archive(stored.path):
        archive_result = _extract(stored, destination_dir, ArchiveLimits.from_config(limits))
        files = [_adopt(entry.member, entry.path) for entry in archive_result.files]

    make_read_only(destination_dir)

    detection = detect(
        stored.path,
        filename=stored.filename,
        override=log_type_override,
    )
    # Every stored file is detected, not just the upload: an archive's members
    # are the records that will actually be parsed. For a plain upload ``files``
    # is the stored file alone, so this stays a single-element list.
    detections = [
        detection
        if file is stored
        else detect(file.path, filename=file.filename, override=log_type_override)
        for file in files
    ]
    return IntakeResult(
        stored=stored,
        detection=detection,
        archive=archive_result,
        files=files,
        detections=detections,
    )


def _adopt(member: str, path: Path) -> StoredFile:
    """Describe an extracted file the same way an uploaded one is described."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_BYTES), b""):
            digest.update(chunk)
    return StoredFile(
        path=path, filename=member, size=path.stat().st_size, sha256=digest.hexdigest()
    )


def intake_path(
    path: Path,
    destination_dir: Path,
    *,
    settings: Settings,
    log_type_override: str | None = None,
    expand_archives: bool = True,
) -> IntakeResult:
    """Intake a file already on disk, such as a validated from-path import."""
    handle = path.open("rb")
    try:
        return intake_stream(
            handle,
            destination_dir,
            path.name,
            settings=settings,
            log_type_override=log_type_override,
            expand_archives=expand_archives,
        )
    finally:
        # The handle is closed here, never in the caller: the import path gets
        # the stream it is given, and an unclosed handle would pin the original
        # file on Windows, breaking the "copy, never hold the original" rule.
        handle.close()


def remove_stored(destination_dir: Path) -> None:
    """Delete everything intake wrote for one source.

    Stored files are read-only, and Windows refuses to delete a read-only file,
    so the write bits are restored first. Deletion is best-effort per entry: one
    file held open by another process must not leave the rest of the tree behind.
    """
    if not destination_dir.exists():
        return
    for path in sorted(destination_dir.rglob("*"), reverse=True):
        with contextlib.suppress(OSError):
            path.chmod(_WRITABLE_MODE)
        with contextlib.suppress(OSError):
            path.unlink() if path.is_file() else path.rmdir()
    with contextlib.suppress(OSError):
        destination_dir.rmdir()


#: Mode restored on stored files so they can be deleted again.
_WRITABLE_MODE = 0o700


__all__ = [
    "MAX_FILENAME_LENGTH",
    "IntakeResult",
    "StoredFile",
    "intake_path",
    "intake_stream",
    "remove_stored",
    "safe_filename",
    "store_file",
    "store_stream",
]
