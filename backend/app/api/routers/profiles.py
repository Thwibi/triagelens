"""Mapping-profile endpoints (spec 03 section 6, spec 06 section 3).

The generic JSON and CSV parsers are only as good as the profile that maps a
record onto the normalized columns. This router lets the UI list, inspect,
save, import, delete and preview those profiles, so a format nobody wrote a
parser for can still be ingested.

Two directories are involved. The shipped profiles live with the build and are
read-only; operator profiles live in a user directory and are the only ones this
router writes. A user profile may shadow a shipped one by name, which is how a
bundled mapping is corrected without editing the bundle. A name that exists only
as a shipped profile cannot be written or deleted at all - ``409`` - so the
bundle stays a fixed point the UI can compare against.

Nothing here touches the database: a profile is a file, and the loader already
owns validation and the mtime cache. Saving a profile invalidates that cache so
the next parse sees the change without a restart.
"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path
from typing import Any

from fastapi import APIRouter, File, Form, UploadFile
from pydantic import BaseModel, Field

from app.errors import ApiError, ErrorCode
from app.ingest.parsers.base import ParseContext, ParseFailure
from app.ingest.parsers.generic_common import (
    invalidate_profile_cache,
    profiles_dir,
    user_profiles_dir,
)
from app.ingest.parsers.generic_csv import GenericCsvParser
from app.ingest.parsers.generic_json import GenericJsonParser
from app.ingest.profiles import Profile, ProfileError, load_profile, load_profiles

router = APIRouter(prefix="/profiles", tags=["profiles"])

#: A profile name becomes a file name, so it must not be able to escape its
#: directory or collide with a path separator.
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

#: The log types a preview can render through the profile engine.
_PREVIEW_LOG_TYPES = frozenset({"generic_csv", "generic_json"})

#: How many normalized rows a preview returns by default (spec 03 section 6).
DEFAULT_PREVIEW_ROWS = 20


class ProfileWrite(BaseModel):
    """Body of ``PUT /profiles/{name}`` and the import form's fallback."""

    yaml: str = Field(min_length=1)


class PreviewRequest(BaseModel):
    """Body of ``POST /profiles/preview``."""

    sample: str = Field(min_length=1)
    yaml: str = Field(min_length=1)
    log_type: str | None = None
    limit: int = Field(default=DEFAULT_PREVIEW_ROWS, ge=1, le=100)


@router.get("")
def list_profiles() -> dict[str, Any]:
    """Every available profile, shipped and user, with its origin."""
    shipped = load_profiles(profiles_dir())
    user = load_profiles(user_profiles_dir())
    effective = {**shipped, **user}
    items = [
        _profile_detail(effective[name], builtin=name in shipped and name not in user)
        for name in sorted(effective)
    ]
    return {"items": items, "total": len(items)}


@router.get("/{name}")
def get_profile(name: str) -> dict[str, Any]:
    """One profile, with its YAML source for the editor."""
    profile, path, builtin = _require_profile(name)
    detail = _profile_detail(profile, builtin=builtin)
    detail["yaml"] = path.read_text(encoding="utf-8")
    return detail


@router.put("/{name}")
def save_profile(name: str, body: ProfileWrite) -> dict[str, Any]:
    """Create or replace a user profile.

    The YAML must declare the same name as the URL; anything else would let a
    request write a profile under a name the caller did not ask for, and the UI
    could then not find what it just saved.
    """
    profile = _parse_yaml(body.yaml, name)
    _reject_builtin(name)
    _write_user_profile(name, body.yaml)
    invalidate_profile_cache()
    return _profile_detail(profile, builtin=False)


@router.post("/import", status_code=201)
def import_profile(
    file: UploadFile = File(...),
    name: str | None = Form(None),
) -> dict[str, Any]:
    """Save a profile uploaded as a YAML file.

    The declared name wins by default; ``name`` overrides it, which is how the
    UI resolves a collision the operator accepts.
    """
    text = _read_upload(file)
    declared = _parse_yaml(text, "")
    target = name or declared.name
    profile = _parse_yaml(text, target) if name is not None else declared
    _reject_builtin(target)
    _write_user_profile(target, text)
    invalidate_profile_cache()
    return _profile_detail(profile, builtin=False)


@router.delete("/{name}")
def delete_profile(name: str) -> dict[str, Any]:
    """Delete a user profile."""
    _reject_builtin(name)
    _require_name(name)
    path = user_profiles_dir() / f"{name}.yaml"
    if not path.is_file():
        raise ApiError(ErrorCode.NOT_FOUND, "profile not found", name=name)
    path.unlink()
    invalidate_profile_cache()
    return {"name": name, "deleted": True}


@router.post("/preview")
def preview_profile(body: PreviewRequest) -> dict[str, Any]:
    """Parse a sample through a profile and return the normalized rows.

    This is the "Custom mapping" dry run from spec 03 section 6: the operator
    pastes a record, maps it, and sees the columns before saving anything. The
    sample is written to a scratch file because a parser reads from a path; it
    never reaches the case store.
    """
    profile = _parse_yaml(body.yaml, "")
    log_type = body.log_type or _guess_log_type(body.sample)
    if log_type not in _PREVIEW_LOG_TYPES:
        raise ApiError(
            ErrorCode.VALIDATION_ERROR,
            "preview supports only generic_csv and generic_json",
            log_type=log_type,
        )
    parser = (
        GenericJsonParser({profile.name: profile})
        if log_type == "generic_json"
        else GenericCsvParser({profile.name: profile})
    )
    rows, errors = _parse_preview(parser, body.sample, log_type, body.limit)
    return {
        "log_type": log_type,
        "rows": rows,
        "errors": errors,
        "row_count": len(rows),
        "error_count": len(errors),
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_name(name: str) -> None:
    """Reject a name that cannot safely become a file name."""
    if not _NAME.match(name):
        raise ApiError(ErrorCode.VALIDATION_ERROR, "invalid profile name", name=name)


def _reject_builtin(name: str) -> None:
    """Refuse to write or delete a profile that ships with the build."""
    _require_name(name)
    if name in load_profiles(profiles_dir()) and name not in load_profiles(user_profiles_dir()):
        raise ApiError(
            ErrorCode.CONFLICT,
            "a built-in profile cannot be modified or deleted",
            name=name,
        )


def _require_profile(name: str) -> tuple[Profile, Path, bool]:
    """The effective profile for ``name``, its file, and whether it is built in."""
    shipped = load_profiles(profiles_dir())
    user = load_profiles(user_profiles_dir())
    if name in user:
        return user[name], user_profiles_dir() / f"{name}.yaml", False
    if name in shipped:
        return shipped[name], profiles_dir() / f"{name}.yaml", True
    raise ApiError(ErrorCode.NOT_FOUND, "profile not found", name=name)


def _parse_yaml(text: str, expected_name: str) -> Profile:
    """Validate YAML text as a profile, optionally enforcing its name."""
    with tempfile.TemporaryDirectory() as scratch:
        path = Path(scratch) / "profile.yaml"
        path.write_text(text, encoding="utf-8")
        try:
            profile = load_profile(path)
        except ProfileError as error:
            raise ApiError(
                ErrorCode.VALIDATION_ERROR, "profile is not valid", detail=str(error)
            ) from error
    if expected_name and profile.name != expected_name:
        raise ApiError(
            ErrorCode.VALIDATION_ERROR,
            "the profile name does not match the requested name",
            name=profile.name,
            requested=expected_name,
        )
    return profile


def _write_user_profile(name: str, text: str) -> None:
    """Write the profile into the user directory, creating it if needed."""
    directory = user_profiles_dir()
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{name}.yaml").write_text(text, encoding="utf-8")


def _read_upload(file: UploadFile) -> str:
    """Read an uploaded profile as UTF-8 text."""
    try:
        return file.file.read().decode("utf-8")
    except UnicodeDecodeError as error:
        raise ApiError(ErrorCode.VALIDATION_ERROR, "profile must be UTF-8 text") from error
    finally:
        file.file.close()


def _guess_log_type(sample: str) -> str:
    """JSON for a sample whose first real line opens an object or array, else CSV."""
    for line in sample.splitlines():
        if line.strip():
            return "generic_json" if line.lstrip()[0] in "{[" else "generic_csv"
    return "generic_csv"


def _parse_preview(
    parser: Any, sample: str, log_type: str, limit: int
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Run a parser over the sample and collect up to ``limit`` rows and errors."""
    suffix = ".json" if log_type == "generic_json" else ".csv"
    with tempfile.TemporaryDirectory() as scratch:
        path = Path(scratch) / f"sample{suffix}"
        path.write_text(sample, encoding="utf-8")
        context = ParseContext(
            case_id="preview",
            source_id="preview",
            filename=path.name,
            path=path,
            max_line_bytes=1 << 20,
        )
        rows: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        for item in parser.parse(context):
            if isinstance(item, ParseFailure):
                if len(errors) < limit:
                    errors.append({"record_ref": item.record_ref, "reason": item.reason})
            elif len(rows) < limit:
                rows.append(_preview_row(item))
    return rows, errors


def _preview_row(event: Any) -> dict[str, Any]:
    """One normalized event as short JSON for the preview table."""
    row = event.to_dict()
    row.pop("case_id", None)
    row.pop("source_id", None)
    row["fields"] = row.pop("fields_json", {})
    return row


def _profile_detail(profile: Profile, *, builtin: bool) -> dict[str, Any]:
    """A profile as the API returns it, without its raw YAML."""
    return {
        "name": profile.name,
        "builtin": builtin,
        "timestamp": {"path": profile.timestamp_path, "format": profile.timestamp_format},
        "timezone": profile.timezone,
        "default_category": profile.default_category,
        "applies_when": {"any_key": sorted(profile.applies_when_keys)},
        "fields": dict(profile.fields),
        "category_rules": [
            {"when": dict(rule.conditions), "ls_category": rule.ls_category}
            for rule in profile.category_rules
        ],
    }


__all__ = [
    "DEFAULT_PREVIEW_ROWS",
    "PreviewRequest",
    "ProfileWrite",
    "router",
]
