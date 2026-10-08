"""Shared Linux syslog framing and message parsing (spec 03 section 3).

``linux_syslog`` and ``linux_auth`` read the same three wire formats and the same
daemon messages, so the work lives here once. A record is framed first:

* RFC 3164 (BSD syslog) carries no year, so the year is inferred (spec 09 P-05).
* RFC 3339 (rsyslog's timestamped form) and RFC 5424 carry a full timestamp.

Every framing is tried in turn on each line rather than one being chosen per
file, because a single collection can interleave all three (a relay writing
RFC 3339 beside an appliance writing RFC 3164).

The mapping onto normalized columns is the table in spec 03 section 3.1. A
message that matches no row still produces an event: the message is evidence on
its own, and dropping it would lose the very lines an analyst is hunting for.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.ingest.normalize import clean_text, parse_timestamp, to_int, year_from
from app.ingest.parsers.base import ParseContext
from app.util.time import localize, to_utc_ms

#: An RFC 3164 timestamp is exactly ``Mon dd HH:MM:SS``.
_BSD_FIELDS = 3

#: The framings, tried in order. RFC 5424 is first because it is the only one
#: that starts with a ``<PRI>`` immediately followed by a version digit, so a
#: plain RFC 3164 line with a leading priority cannot be mistaken for it.
_FRAMING: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "rfc5424",
        re.compile(
            r"^<(?P<pri>\d{1,3})>(?P<version>\d)\s(?P<ts>\S+)\s(?P<host>\S+)\s"
            r"(?P<tag>\S+)\s(?P<pid>\S+)\s(?P<msgid>\S+)\s"
            r"(?P<structured>-|(?:\[[^\]]*\])+)\s?(?P<message>.*)$"
        ),
    ),
    (
        "rfc3164",
        re.compile(
            r"^(?:<(?P<pri>\d{1,3})>)?"
            r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
            r"(?P<host>\S+)\s+(?P<tag>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s?"
            r"(?P<message>.*)$"
        ),
    ),
    (
        "rfc3339",
        re.compile(
            r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?"
            r"(?:Z|[+-]\d{2}:\d{2}))\s+(?P<host>\S+)\s"
            r"(?P<tag>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<message>.*)$"
        ),
    ),
)

#: English month abbreviations used by RFC 3164. Parsed by table rather than
#: ``%b`` so a host with a non-English locale cannot reinterpret a timestamp.
_MONTHS: dict[str, int] = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}

#: The syslog severity behind ``pri & 7`` (spec 03 section 3.1).
_PRI_LEVELS: dict[int, str] = {
    0: "critical",
    1: "critical",
    2: "critical",
    3: "error",
    4: "warning",
    5: "info",
    6: "info",
    7: "debug",
}

#: Daemons whose messages make a file an authentication log (spec 03 section 3.1).
AUTH_APPS: frozenset[str] = frozenset(
    {
        "sshd",
        "sudo",
        "su",
        "login",
        "passwd",
        "useradd",
        "usermod",
        "userdel",
        "groupadd",
        "cron",
        "crond",
        "polkitd",
        "systemd-logind",
    }
)

#: Prefixes that also mark an authentication daemon (``pam_unix``, ``pam_...``).
_AUTH_PREFIXES = ("pam",)


def is_auth_app(name: str | None) -> bool:
    """True when a syslog tag names an authentication daemon."""
    text = clean_text(name)
    if text is None:
        return False
    lowered = text.lower()
    return lowered in AUTH_APPS or lowered.startswith(_AUTH_PREFIXES)


@dataclass(slots=True)
class Framed:
    """One line split into the fields a syslog framing exposes."""

    framing: str
    pri: int | None
    ts: str | None
    host: str | None
    app: str | None
    pid: int | None
    message: str


def _or_none(value: Any) -> str | None:
    """A framing group as text, treating the RFC 5424 nil value ``-`` as absent."""
    text = clean_text(value)
    if text is None or text == "-":
        return None
    return text


def match_framing(line: str) -> Framed | None:
    """Split one line into a :class:`Framed`, or ``None`` when no framing matches."""
    for name, pattern in _FRAMING:
        matched = pattern.match(line)
        if matched is None:
            continue
        groups = matched.groupdict()
        app = _or_none(groups.get("tag")) or _or_none(groups.get("app"))
        return Framed(
            framing=name,
            pri=to_int(groups.get("pri")),
            ts=_or_none(groups.get("ts")),
            host=_or_none(groups.get("host")),
            app=app,
            pid=to_int(_or_none(groups.get("pid"))),
            message=groups.get("message") or "",
        )
    return None


def level_from_pri(pri: int | None) -> str | None:
    """Normalized level for a syslog priority, or ``None`` when there is none."""
    if pri is None:
        return None
    return _PRI_LEVELS.get(pri & 7)


def _localized_ms(naive: datetime, tz: str) -> int | None:
    """Attach ``tz`` to a naive wall-clock time and return UTC epoch milliseconds.

    Ambiguous local times (a DST fold) resolve to the earlier reading, which is
    deterministic and always exists; the spec only requires a deterministic
    choice (spec 09 P-05), and a nonexistent spring-forward time localizes
    without error under ``earlier``.
    """
    try:
        return to_utc_ms(localize(naive, tz, ambiguous="earlier"))
    except ValueError:
        return None


def _file_year(path: Path) -> int | None:
    """The year of the file's mtime, the last resort for RFC 3164 timestamps."""
    try:
        return year_from(datetime.fromtimestamp(path.stat().st_mtime, tz=UTC))
    except OSError:
        return None


class SyslogClock:
    """Turns a framing's timestamp into epoch milliseconds for one file.

    RFC 3164 omits the year and can roll over from December to January inside a
    single file. The year is seeded from the operator's ``assumed_year``, then a
    year in the filename, then the file's mtime, and advanced whenever the month
    moves backwards (spec 09 P-05).
    """

    __slots__ = ("_last_month", "_tz", "_year")

    def __init__(self, context: ParseContext) -> None:
        self._tz = context.timezone or "UTC"
        self._year = context.assumed_year or year_from(context.filename) or _file_year(context.path)
        self._last_month: int | None = None

    def epoch_ms(self, framed: Framed) -> int | None:
        """UTC epoch milliseconds for a framed line, or ``None``."""
        if framed.ts is None:
            return None
        if framed.framing == "rfc3164":
            return self._bsd_ms(framed.ts)
        parsed = parse_timestamp(framed.ts, fmt="iso8601", assume_tz=self._tz)
        return parsed[0] if parsed else None

    def _bsd_ms(self, raw_ts: str) -> int | None:
        parts = " ".join(raw_ts.split()).split(" ")
        if len(parts) != _BSD_FIELDS:
            return None
        month = _MONTHS.get(parts[0].lower())
        if month is None or self._year is None:
            return None
        # A month that moves backwards means the file crossed a year boundary.
        if self._last_month is not None and month < self._last_month:
            self._year += 1
        self._last_month = month
        try:
            day = int(parts[1])
            naive = datetime.strptime(
                f"{self._year:04d}-{month:02d}-{day:02d} {parts[2]}",
                "%Y-%m-%d %H:%M:%S",
            )
        except ValueError:
            return None
        return _localized_ms(naive, self._tz)


def level_from_pri_or_info(pri: int | None) -> str:
    """Severity for a framed record; no priority at all is ``info`` (spec 3.1)."""
    return _PRI_LEVELS.get(pri & 7, "info") if pri is not None else "info"


# ---------------------------------------------------------------------------
# The message table (spec 03 section 3.1)
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class MessageMatch:
    """The normalized fields a daemon message contributed."""

    action: str
    category: str | None = None
    outcome: str | None = None
    columns: dict[str, Any] = field(default_factory=dict)
    fields: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class _Pattern:
    """One row of the message table."""

    regex: re.Pattern[str]
    action: str
    category: str | None = None
    outcome: str | None = None
    apps: frozenset[str] | None = None
    columns: tuple[tuple[str, str], ...] = ()
    fields: tuple[tuple[str, str], ...] = ()


def _pattern(
    expression: str,
    action: str,
    *,
    category: str | None = None,
    outcome: str | None = None,
    apps: tuple[str, ...] | None = None,
    columns: tuple[tuple[str, str], ...] = (),
    fields: tuple[tuple[str, str], ...] = (),
) -> _Pattern:
    return _Pattern(
        regex=re.compile(expression),
        action=action,
        category=category,
        outcome=outcome,
        apps=frozenset(apps) if apps is not None else None,
        columns=columns,
        fields=fields,
    )


#: ``user_name``/``src_ip``/``src_port`` shared by the logon-shaped ssh rows.
_SSH_COLUMNS: tuple[tuple[str, str], ...] = (
    ("user_name", "user"),
    ("src_ip", "ip"),
    ("src_port", "port"),
)

#: The ordered table. First match wins; a row with ``apps`` only fires for that
#: daemon. An ssh pattern is deliberately unanchored so the daemon's prefix
#: ("Failed password for ...") is found wherever it sits in the message.
_PATTERNS: tuple[_Pattern, ...] = (
    _pattern(
        r"Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) "
        r"port (?P<port>\d+)",
        "ssh_failed_password",
        category="logon",
        outcome="failure",
        columns=_SSH_COLUMNS,
        fields=(("auth_method", "method"),),
    ),
    _pattern(
        r"Accepted (?P<method>password|publickey|keyboard-interactive/pam|hostbased|gssapi\S*) "
        r"for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)",
        "ssh_accepted_login",
        category="logon",
        outcome="success",
        columns=_SSH_COLUMNS,
        fields=(("auth_method", "method"),),
    ),
    _pattern(
        r"Invalid user (?P<user>\S*) from (?P<ip>\S+)(?: port (?P<port>\d+))?",
        "ssh_invalid_user",
        category="logon",
        outcome="failure",
        columns=_SSH_COLUMNS,
    ),
    _pattern(
        r"Connection closed by (?:authenticating user (?P<user>\S+) )?(?P<ip>\S+) "
        r"port (?P<port>\d+)",
        "ssh_connection_closed",
        category="logon",
        columns=_SSH_COLUMNS,
    ),
    _pattern(
        r"Disconnected from (?:authenticating |invalid )?user (?P<user>\S+) (?P<ip>\S+) "
        r"port (?P<port>\d+)",
        "ssh_disconnected",
        category="logon",
        columns=_SSH_COLUMNS,
    ),
    _pattern(
        r"Did not receive identification string from (?P<ip>\S+)",
        "ssh_no_identification",
        category="logon",
        columns=(("src_ip", "ip"),),
    ),
    _pattern(
        r"^\s*(?P<user>\S+)\s*:\s*(?:TTY=(?P<tty>\S+)\s*;\s*)?PWD=(?P<pwd>.*?)\s*;\s*"
        r"USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<cmd>.*)$",
        "sudo_command",
        category="process_creation",
        apps=("sudo",),
        columns=(
            ("user_name", "user"),
            ("target_user_name", "target"),
            ("process_cmdline", "cmd"),
            ("file_path", "pwd"),
        ),
    ),
    _pattern(
        r"(?P<user>\S+) : (?P<n>\d+) incorrect password attempts?",
        "sudo_auth_failure",
        category="logon",
        outcome="failure",
        columns=(("user_name", "user"),),
    ),
    _pattern(
        r"pam_unix\(su(?:-l)?:session\): session opened for user (?P<target>\S+)"
        r"(?: \(uid=\d+\))? by (?:\(uid=\d+\)|(?P<user>\S+)\(uid=\d+\))",
        "su_session_opened",
        category="logon",
        outcome="success",
        columns=(("user_name", "user"), ("target_user_name", "target")),
    ),
    _pattern(
        r"FAILED SU \(to (?P<target>\S+)\) (?P<user>\S+) on",
        "su_failed",
        category="logon",
        outcome="failure",
    ),
    _pattern(
        r"new user: name=(?P<name>[^,]+), UID=(?P<uid>\d+), GID=(?P<gid>\d+), "
        r"home=(?P<home>[^,]+), shell=(?P<shell>\S+)",
        "user_added",
        category="account_management",
        columns=(("target_user_name", "name"),),
    ),
    _pattern(
        r"delete user '(?P<name>[^']+)'",
        "user_deleted",
        category="account_management",
        columns=(("target_user_name", "name"),),
    ),
    _pattern(
        r"add '(?P<name>[^']+)' to (?:shadow )?group '(?P<grp>[^']+)'",
        "group_member_added",
        category="account_management",
        columns=(("target_user_name", "name"),),
    ),
    _pattern(
        r"\((?P<user>[^)]+)\) CMD \((?P<cmd>.*)\)",
        "cron_command",
        category="process_creation",
        apps=("cron", "crond"),
        columns=(("user_name", "user"), ("process_cmdline", "cmd")),
    ),
    _pattern(
        r"\((?P<user>[^)]+)\) (?:REPLACE|BEGIN EDIT|END EDIT|DELETE) \(",
        "crontab_modified",
        apps=("cron", "crond"),
        columns=(("user_name", "user"),),
    ),
    _pattern(
        r"Started (?P<unit>.+)\.$",
        "service_started",
        apps=("systemd",),
        columns=(("message", "unit"),),
    ),
    _pattern(
        r"Stopped (?P<unit>.+)\.$",
        "service_stopped",
        apps=("systemd",),
        columns=(("message", "unit"),),
    ),
)


def match_message(message: str, app: str | None) -> MessageMatch | None:
    """The first table row whose pattern matches ``message`` for ``app``."""
    app_key = (clean_text(app) or "").lower()
    for pattern in _PATTERNS:
        if pattern.apps is not None and app_key not in pattern.apps:
            continue
        matched = pattern.regex.search(message)
        if matched is None:
            continue
        columns: dict[str, Any] = {}
        for column, group in pattern.columns:
            value = matched.group(group)
            if value is not None:
                columns[column] = value
        fields = {
            key: matched.group(group)
            for key, group in pattern.fields
            if matched.group(group) is not None
        }
        return MessageMatch(pattern.action, pattern.category, pattern.outcome, columns, fields)
    return None


__all__ = [
    "AUTH_APPS",
    "Framed",
    "MessageMatch",
    "SyslogClock",
    "is_auth_app",
    "level_from_pri",
    "level_from_pri_or_info",
    "match_framing",
    "match_message",
]
