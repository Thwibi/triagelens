"""Fallback ATT&CK mappings for untagged detections (spec 04 section 7.3).

``data/mitre_fallbacks.yaml`` maps an event's channel/event_id or
event_action to techniques, so builtin and custom rules without Sigma
tags still land somewhere sensible. Mappings resolved this way are
labelled ``source: fallback`` in the alert detail ("inferred" in the UI).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass(frozen=True, slots=True)
class FallbackEntry:
    """One ``when`` -> techniques mapping from the fallback file."""

    channel: str | None
    event_id: int | None
    event_action: str | None
    techniques: tuple[str, ...]


def load_fallbacks(path: Path | str) -> tuple[FallbackEntry, ...]:
    """Parse ``mitre_fallbacks.yaml``; a missing file maps nothing.

    Each entry must carry at least one ``when`` condition and a non-empty
    ``techniques`` list; anything else raises so a broken shipped file is
    caught at startup rather than silently mapping everything.
    """
    file = Path(path)
    if not file.is_file():
        return ()
    try:
        text = file.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"cannot read mitre_fallbacks.yaml: {exc}") from exc
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid mitre_fallbacks.yaml: {exc}") from exc
    if document is None:
        return ()
    if not isinstance(document, list):
        raise TypeError("mitre_fallbacks.yaml must be a list of entries")
    return tuple(_entry(index, item) for index, item in enumerate(document))


def _entry(index: int, item: object) -> FallbackEntry:
    if not isinstance(item, dict):
        raise TypeError(f"fallback entry {index} is not a mapping")
    when = item.get("when")
    if not isinstance(when, dict) or not when:
        raise ValueError(f"fallback entry {index} has no recognisable condition")
    channel = when.get("channel")
    event_id = when.get("event_id")
    event_action = when.get("event_action")
    if channel is None and event_id is None and event_action is None:
        raise ValueError(f"fallback entry {index} has no recognisable condition")
    techniques = item.get("techniques")
    if not isinstance(techniques, list) or not techniques:
        raise ValueError(f"fallback entry {index} lists no techniques")
    return FallbackEntry(
        channel=str(channel) if channel is not None else None,
        event_id=int(event_id) if event_id is not None else None,
        event_action=str(event_action) if event_action is not None else None,
        techniques=tuple(str(value) for value in techniques),
    )


def match_fallback(
    entries: Iterable[FallbackEntry],
    *,
    channel: str | None,
    event_id: int | None,
    event_action: str | None,
) -> tuple[str, ...]:
    """Techniques from every entry whose ``when`` clause matches, deduped.

    Channel and event_action comparisons are case-insensitive; an absent
    event field never satisfies a condition that names one.
    """
    found: list[str] = []
    for entry in entries:
        if entry.channel is not None and (channel or "").casefold() != entry.channel.casefold():
            continue
        if entry.event_id is not None and event_id != entry.event_id:
            continue
        if (
            entry.event_action is not None
            and (event_action or "").casefold() != entry.event_action.casefold()
        ):
            continue
        found.extend(entry.techniques)
    return tuple(dict.fromkeys(found))


__all__ = ["FallbackEntry", "load_fallbacks", "match_fallback"]
