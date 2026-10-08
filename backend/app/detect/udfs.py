"""SQLite user functions used by compiled detections (spec 04 section 2).

These are registered only on the long-lived detection read connection, never on
the writer: they are pure functions over already-stored rows, and keeping them
off the writer means one runaway regex cannot stall ingestion.

``regexp`` sits behind SQLite's ``X REGEXP Y`` operator, which calls the user
function as ``regexp(pattern, value)``.

A hostile regex can still stall the worker: the stdlib ``re`` engine offers no
timeouts, so this module fences the attack surface with (a) a bounded compiled
pattern cache keyed by text, (b) a rejection of rule patterns carrying the
classic catastrophic-backtracking shapes (nested quantifiers, backrefs inside a
quantified group), and (c) ``fullmatch`` semantics per the Sigma ``|re``
modifier, which cannot anchor other regexes (so a ``|re`` rule never degrades
to a raw ``LIKE``). The same verdict the fence reaches is exposed as
:func:`pattern_problem`, so the engine can reject a hostile pattern once,
before execution, with a reason to record in ``rule_runs`` instead of a
silently non-matching filter.

``cidr_match`` is what the backend compiles ``|cidr`` into instead of an OR
explosion; it also survives values SQLite cannot coerce to an IP by returning
``False``.
"""

from __future__ import annotations

import ipaddress
import re
import sqlite3
import threading
from typing import Any

#: Upper bound on distinct patterns kept in the compile cache. Compiled
#: :class:`re.Pattern` objects are not bounded by SQLite's own caches, and rules
#: are only counted in the hundreds; 512 keeps memory flat while letting the
#: hottest regular expressions skip recompilation on every event.
REGEX_CACHE_SIZE = 512

#: Patterns regular enough to be "mimikatz"-style that are rejected outright.
#: Each alternation sits underneath the top-level match and, when combined with
#: a large value, makes the backtracker blow up. See the module docstring.
_EVIL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\((?:[^()]|\\.)*+\)(?:[*+{][^}]*}?)*"),  # quantifier on a group
    re.compile(r"\\\d+\s*[*+]"),  # quantified backreference
    re.compile(r"[+*]{2,}"),  # doubled quantifier
)

#: Value/pattern size fences so a single event cannot carry megabytes of text
#: or a kilobyte of pattern into the engine accidentally.
_MAX_PATTERN_BYTES = 2048
_MAX_VALUE_CODEPOINTS = 262_144

_CACHE_LOCK = threading.Lock()
_PATTERN_CACHE: dict[str, re.Pattern[str] | None] = {}


def _size_or_shape_problem(pattern: str) -> str | None:
    """Cheap empty/size/shape rejection; ``None`` when the pattern may run."""
    if not pattern:
        return "empty pattern"
    if len(pattern) > _MAX_PATTERN_BYTES:
        return f"pattern longer than {_MAX_PATTERN_BYTES} bytes"
    if any(evil.search(pattern) for evil in _EVIL_PATTERNS):
        return "catastrophic-backtracking shape"
    return None


def pattern_problem(pattern: str) -> str | None:
    """Why ``pattern`` must not run against event data, or ``None`` if it may.

    The engine calls this for every ``|re`` pattern before executing a rule
    (spec 04 section 2): Python's ``re`` cannot be interrupted, so an
    unusable pattern is rule health reported once with a reason - never a
    silent non-match or a stalled worker. :func:`_compiled` reaches the same
    verdict through :func:`_size_or_shape_problem`, so a pattern rejected
    here can never run in ``regexp`` either.
    """
    problem = _size_or_shape_problem(pattern)
    if problem is not None:
        return problem
    try:
        re.compile(pattern)
    except re.error as exc:
        return f"does not compile: {exc}"
    return None


def _compiled(pattern: str) -> re.Pattern[str] | None:
    """Cached, validated pattern; ``None`` for anything unusable."""
    if _size_or_shape_problem(pattern) is not None:
        return None
    with _CACHE_LOCK:
        if pattern in _PATTERN_CACHE:
            return _PATTERN_CACHE[pattern]
        if len(_PATTERN_CACHE) >= REGEX_CACHE_SIZE:
            _PATTERN_CACHE.clear()
        try:
            compiled: re.Pattern[str] | None = re.compile(pattern)
        except re.error:
            compiled = None
        _PATTERN_CACHE[pattern] = compiled
        return compiled


def regexp(pattern: str, value: Any) -> bool:
    """True when ``value`` fully matches ``pattern`` (``X REGEXP Y`` order)."""
    if value is None:
        return False
    compiled = _compiled(pattern)
    if compiled is None:
        return False
    text = str(value)
    if len(text) > _MAX_VALUE_CODEPOINTS:
        return False
    try:
        return compiled.fullmatch(text) is not None
    except (re.error, RuntimeError, RecursionError):
        return False


def cidr_match(value: Any, network: str) -> bool:
    """True when ``value`` parses as an IP inside ``network``."""
    if value is None:
        return False
    text = str(value).strip()
    if not text:
        return False
    # IPv6 zone ids (``fe80::1%eth0``) are a link scope, not part of the address.
    try:
        address = ipaddress.ip_address(text.split("%", 1)[0])
        net = ipaddress.ip_network(network, strict=False)
    except ValueError:
        return False
    return address in net


def register_udfs(connection: sqlite3.Connection) -> None:
    """Bind the detection engine's user functions to ``connection``."""
    connection.create_function("regexp", 2, regexp, deterministic=True)
    connection.create_function("cidr_match", 2, cidr_match, deterministic=True)


__all__ = [
    "REGEX_CACHE_SIZE",
    "cidr_match",
    "pattern_problem",
    "regexp",
    "register_udfs",
]
