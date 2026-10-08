"""Shared machinery for the generic JSON and CSV parsers (spec 03 section 6).

The two parsers differ only in how they turn a file into records: JSON walks
objects, CSV walks header-labelled rows. Once a record is a mapping, the mapping
profile engine treats them identically, so that half lives here instead of being
written twice and drifting.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from app.ingest.events import NormalizedEvent
from app.ingest.normalize import (
    canonical_ip,
    clean_text,
    normalize_level,
    normalize_outcome,
    parse_timestamp,
    to_int,
    to_port,
    truncate,
)
from app.ingest.parsers.base import ParseContext
from app.ingest.profiles import Profile, flatten, load_profiles, resolve

#: Environment variable naming an alternate user-profile directory. Tests and
#: desktop installs use it; unset means the bundled ``data/profiles/user``.
USER_PROFILES_ENV = "TRIAGELENS_USER_PROFILES_DIR"


def profiles_dir() -> Path:
    """Directory holding the shipped profiles, ``backend/data/profiles``."""
    return Path(__file__).resolve().parents[3] / "data" / "profiles"


def user_profiles_dir() -> Path:
    """Directory holding user-saved profiles."""
    override = os.environ.get(USER_PROFILES_ENV)
    if override:
        return Path(override)
    return profiles_dir() / "user"


#: Holder for the last successful load: shipped + user profiles, with a stamp.
_PROFILE_CACHE: dict[str, tuple[dict[str, Profile], tuple[tuple[str, int], ...]]] = {}


def load_profiles_cached() -> dict[str, Profile]:
    """Profiles from disk (shipped plus user), re-read when a directory changes.

    Cached because a parse worker loads this once per source and the directories
    are tiny; the mtime check keeps a profile edited through the API from being
    ignored until restart. A user profile with the same name as a shipped one
    wins, so an operator can shadow a built-in without editing the bundle.
    """
    shipped = profiles_dir()
    user = user_profiles_dir()
    stamp = (*_dir_stamp(shipped), *(() if user == shipped else _dir_stamp(user)))
    cached = _PROFILE_CACHE.get("entry")
    if cached is not None and cached[1] == stamp:
        return cached[0]
    profiles = load_profiles(shipped)
    if user != shipped:
        profiles.update(load_profiles(user))
    _PROFILE_CACHE["entry"] = (profiles, stamp)
    return profiles


def invalidate_profile_cache() -> None:
    """Drop the cache so the next load re-reads the directories."""
    _PROFILE_CACHE.pop("entry", None)


def _dir_stamp(directory: Path) -> tuple[tuple[str, int], ...]:
    """Sorted (name, mtime) of the profile files, for cache invalidation."""
    if not directory.is_dir():
        return ()
    return tuple(sorted((path.name, path.stat().st_mtime_ns) for path in directory.glob("*.y*ml")))


def pick_profile(record: dict[str, Any], profiles: dict[str, Profile]) -> Profile | None:
    """The most specific profile claiming this record.

    Specificity is the number of ``applies_when`` keys, so a profile naming the
    exact columns of a vendor export beats a generic unconditional one.
    """
    best: Profile | None = None
    best_score = -1
    for profile in profiles.values():
        if not profile.applies_to(record):
            continue
        score = len(profile.applies_when_keys)
        if score > best_score:
            best, best_score = profile, score
    return best


def fields_json(record: dict[str, Any], profile: Profile) -> dict[str, Any]:
    """Every original field, plus an address that failed validation.

    Spec 02 section 2: an invalid IP never reaches a column but must not vanish.
    It is re-attached here under ``*_raw`` so the evidence survives.
    """
    result: dict[str, Any] = dict(flatten(record))
    for column in ("src_ip", "dst_ip"):
        path = profile.fields.get(column)
        value = resolve(record, path) if path else None
        if value is not None and canonical_ip(value) is None:
            result[f"{column}_raw"] = value
    return result


def map_record(
    *,
    context: ParseContext,
    profile: Profile,
    record: dict[str, Any],
    record_ref: str,
    raw: str,
    log_type: str,
) -> NormalizedEvent:
    """Map one record through a profile into an event."""
    values: dict[str, Any] = {}
    for name, path in profile.fields.items():
        values[name] = resolve(record, path)

    timestamp = parse_timestamp(
        resolve(record, profile.timestamp_path),
        fmt=profile.timestamp_format,
        assume_tz=profile.timezone or context.timezone,
    )
    clipped_raw, _ = truncate(raw, context.max_line_bytes)

    return NormalizedEvent(
        case_id=context.case_id,
        source_id=context.source_id,
        record_ref=record_ref,
        log_type=log_type,
        raw=clipped_raw,
        ts_ms=timestamp[0] if timestamp else None,
        ls_category=profile.category_for(record),
        host=clean_text(values.get("host")),
        event_id=to_int(values.get("event_id")),
        level=normalize_level(values.get("level")),
        event_action=clean_text(values.get("event_action")),
        event_outcome=normalize_outcome(values.get("event_outcome")),
        user_name=clean_text(values.get("user_name")),
        src_ip=canonical_ip(values.get("src_ip")),
        src_port=to_port(values.get("src_port")),
        dst_ip=canonical_ip(values.get("dst_ip")),
        dst_port=to_port(values.get("dst_port")),
        process_path=clean_text(values.get("process_path")),
        process_cmdline=clean_text(values.get("process_cmdline")),
        parent_process_path=clean_text(values.get("parent_process_path")),
        file_path=clean_text(values.get("file_path")),
        url=clean_text(values.get("url")),
        http_method=clean_text(values.get("http_method")),
        http_status=to_int(values.get("http_status")),
        user_agent=clean_text(values.get("user_agent")),
        message=clean_text(values.get("message")),
        fields_json=fields_json(record, profile),
    )


__all__ = [
    "USER_PROFILES_ENV",
    "fields_json",
    "invalidate_profile_cache",
    "load_profiles_cached",
    "map_record",
    "pick_profile",
    "profiles_dir",
    "user_profiles_dir",
]
