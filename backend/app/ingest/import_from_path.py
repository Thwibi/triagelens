"""Importing evidence from a path on the server (spec 03 section 5).

This is the most dangerous entry point in the product: the operator is asked to
name a path on the host, and the process will read it. The rules that make it
safe are all about proving that the path is one the operator was allowed to
offer:

- The path is resolved **before** anything is read, so a symlink pointing at
  ``/etc/shadow`` is judged by where it lands, not by where it appears to point.
- The resolved path must be inside one of ``storage.allowed_import_roots``.
  Containment is checked with :meth:`pathlib.PurePath.is_relative_to` on resolved
  paths, so neither ``..`` nor a symlink can step outside.
- The target must be a regular file. A directory, device, fifo or socket is
  refused.
- The file is **copied**, never moved or linked. Importing must not be able to
  destroy or alias the operator's original evidence.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path, PurePath

from app.config import Settings
from app.errors import ApiError, ErrorCode


@dataclass(frozen=True, slots=True)
class ImportCandidate:
    """A resolved, validated path that may be imported."""

    path: Path
    size: int

    @property
    def name(self) -> str:
        """The filename to store it under."""
        return self.path.name


def _forbidden(message: str, **details: object) -> ApiError:
    """A path the operator is not allowed to import."""
    return ApiError(ErrorCode.FORBIDDEN_PATH, message, **details)


def resolve_import_path(raw: str | os.PathLike[str], settings: Settings) -> ImportCandidate:
    """Validate one path for import, or refuse it.

    Args:
        raw: The path as supplied by the operator. It may be relative, which is
            resolved against the current working directory before any check.
        settings: Supplies the allowed import roots.

    Returns:
        The resolved path and its size.

    Raises:
        ApiError: ``FORBIDDEN_PATH`` when the path is missing, is not a regular
            file, is not inside an allowed root, or cannot be resolved.
    """
    if not str(raw).strip():
        raise _forbidden("no path was supplied")

    try:
        resolved = Path(raw).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as error:
        # RuntimeError covers a symlink loop, which resolve() cannot untangle.
        raise _forbidden(
            "path could not be resolved",
            path=str(raw),
            detail=type(error).__name__,
        ) from None

    if not _within_roots(resolved, settings):
        raise _forbidden(
            "path is outside every allowed import root",
            path=str(resolved),
            allowed_roots=[str(root) for root in settings.resolved_import_roots],
        )

    try:
        info = resolved.stat()
    except OSError as error:
        raise _forbidden(
            "path could not be inspected", path=str(resolved), detail=type(error).__name__
        ) from None

    if not stat.S_ISREG(info.st_mode):
        raise _forbidden(
            "only regular files can be imported",
            path=str(resolved),
        )

    return ImportCandidate(path=resolved, size=info.st_size)


def _within_roots(path: Path, settings: Settings) -> bool:
    """True when ``path`` is inside one of the configured import roots.

    Both sides are already resolved, and the roots are resolved again here so a
    root that is itself a symlink cannot create a gap.
    """
    for root in settings.resolved_import_roots:
        try:
            resolved_root = root.resolve(strict=False)
        except OSError:
            continue
        if path == resolved_root or resolved_root in path.parents:
            return True
    return False


def iter_import_candidates(
    paths: list[str | os.PathLike[str]], settings: Settings
) -> Iterator[ImportCandidate]:
    """Validate several paths, yielding each one that is allowed.

    A path that fails validation is skipped rather than aborting the batch, so one
    mistyped entry in a list of twenty does not discard the other nineteen. The
    caller decides whether skipping is acceptable; it is only safe when the
    caller reports what was skipped.
    """
    for raw in paths:
        try:
            yield resolve_import_path(raw, settings)
        except ApiError:
            continue


def import_candidates(
    raw: str | os.PathLike[str],
    settings: Settings,
    *,
    recursive: bool,
) -> list[ImportCandidate]:
    """Expand one supplied path into the files that may be imported.

    A regular file yields itself. A directory yields every regular file beneath it
    when ``recursive`` is true; without the flag it is refused just like any other
    non-regular path, so a client cannot accidentally blow the request open by
    naming a folder.

    Two rules keep the recursion contained: symlinked subdirectories are never
    descended into (``follow_symlinks=False``), and a symlinked file only counts
    when its target still resolves inside an allowed root. The names are sorted so
    the same directory always imports in the same order.
    """
    if not str(raw).strip():
        raise _forbidden("no path was supplied")

    try:
        resolved = Path(raw).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise _forbidden(
            "path could not be resolved", path=str(raw), detail=type(error).__name__
        ) from None

    if not _within_roots(resolved, settings):
        raise _forbidden(
            "path is outside every allowed import root",
            path=str(resolved),
            allowed_roots=[str(root) for root in settings.resolved_import_roots],
        )

    try:
        info = resolved.stat()
    except OSError as error:
        raise _forbidden(
            "path could not be inspected", path=str(resolved), detail=type(error).__name__
        ) from None

    if stat.S_ISREG(info.st_mode):
        return [ImportCandidate(path=resolved, size=info.st_size)]

    if not stat.S_ISDIR(info.st_mode):
        raise _forbidden("only regular files can be imported", path=str(resolved))
    if not recursive:
        raise _forbidden("a directory can only be imported with recursive=true", path=str(resolved))
    return list(_walk_directory(resolved, settings))


def _walk_directory(root: Path, settings: Settings) -> Iterator[ImportCandidate]:
    """Every importable regular file under ``root``, in sorted order."""
    for directory, names, files in os.walk(root, followlinks=False):
        names[:] = sorted(name for name in names if not (Path(directory) / name).is_symlink())
        for filename in sorted(files):
            candidate = Path(directory) / filename
            if candidate.is_symlink():
                try:
                    target = candidate.resolve(strict=False)
                except OSError:
                    continue
                # A link pointing outside the allowed tree would copy bytes it
                # was never granted; such a link is skipped, not followed.
                if not _within_roots(target, settings):
                    continue
            else:
                target = candidate
            try:
                size = target.stat().st_size
            except OSError:
                continue
            yield ImportCandidate(path=candidate, size=size)


def is_within(path: PurePath, root: PurePath) -> bool:
    """True when ``path`` is ``root`` or lives under it."""
    return path == root or root in path.parents


__all__ = [
    "ImportCandidate",
    "import_candidates",
    "is_within",
    "iter_import_candidates",
    "resolve_import_path",
]
