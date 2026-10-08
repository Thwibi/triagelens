"""Detection run engine (spec 04 section 2).

One pass over the profile-selected rules: route the logsource, prune against
the case's source inventory, compile the Sigma condition, probe field
presence, execute the match query under a per-rule time budget, and hand back
one :class:`RuleExecution` per evaluated rule - a row for every rule, never a
silent skip. Persisting those into ``detection_runs`` / ``rule_runs`` is the
repository's job; aggregating matches into alerts is the layer above.

Two fences guard the pass:

* every ``|re`` pattern is validated with :func:`pattern_problem` before the
  rule reaches SQL, so a catastrophic-backtracking rule is recorded as
  ``error`` with the reason instead of running (Python's ``re`` cannot be
  interrupted - spec 09 D-06);
* everything SQL runs under a ``set_progress_handler`` deadline, so a rule
  that overruns its budget aborts as ``timeout`` while the rest of the run
  continues (spec 09 D-05).

Correlation rules are executed by the correlation stage (spec 04 section 5)
after their base rules; handing one to :func:`execute_rules` is a programming
error.
"""

from __future__ import annotations

import sqlite3
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

import yaml
from sigma.rule import SigmaRule
from sigma.types import SigmaRegularExpression

from app.detect.compile import (
    CompiledDetection,
    CompileError,
    compile_detection,
    referenced_fields,
)
from app.detect.fields import FieldContext, FieldResolver
from app.detect.routing import Route, Unroutable, build_route
from app.detect.udfs import pattern_problem, register_udfs
from app.models.rule import RULE_TYPE_CORRELATION, RuleRecord
from app.models.run import (
    RULE_RUN_ERROR,
    RULE_RUN_OK,
    RULE_RUN_SKIPPED_NO_DATA,
    RULE_RUN_TIMEOUT,
)

#: SQLite statements between progress-handler ticks: high enough that the
#: Python callback stays negligible per statement, low enough that the
#: deadline overshoots by at most a few statements of a slow scan.
_PROGRESS_STEPS = 1000

#: Columns handed up per match - the ``ORDER BY ts_ms, id`` page spec 04
#: section 2 selects, exactly, so the alert layer groups what the query saw.
_MATCH_COLUMNS = "id, ts_ms, host, user_name"


@dataclass(frozen=True, slots=True)
class EventMatch:
    """One matched event, as selected by the rule's query."""

    event_id: int
    ts_ms: int | None
    host: str | None
    user_name: str | None


@dataclass(frozen=True, slots=True)
class RuleOutcome:
    """One ``rule_runs`` row: what the run reports for one rule."""

    rule_id: str
    status: str
    match_count: int
    duration_ms: int
    error: str | None


@dataclass(frozen=True, slots=True)
class RuleExecution:
    """An outcome plus the full match list (``rule_runs`` stores counts only)."""

    outcome: RuleOutcome
    matches: tuple[EventMatch, ...]


@dataclass(frozen=True, slots=True)
class EngineResult:
    """Everything one engine pass evaluated, in evaluation order."""

    executions: tuple[RuleExecution, ...]
    cancelled: bool

    @property
    def outcomes(self) -> tuple[RuleOutcome, ...]:
        """The outcomes only, ready for :meth:`DetectionRunRepository.record_rules`."""
        return tuple(execution.outcome for execution in self.executions)


@dataclass(frozen=True, slots=True)
class _Prepared:
    """Parsed, fenced and routed rule ready for the SQL phase."""

    sigma_rule: SigmaRule
    route: Route


@dataclass(frozen=True, slots=True)
class _Skipped:
    """An early outcome: a rule that must not reach the match query."""

    status: str
    error: str | None


@dataclass(frozen=True, slots=True)
class _Evaluated:
    """A rule that ran to completion: its matches and missing-field names."""

    matches: tuple[EventMatch, ...]
    missing: tuple[str, ...]


def execute_rules(
    connection: sqlite3.Connection,
    *,
    case_id: str,
    rules: Sequence[RuleRecord],
    logsource_map: dict[str, dict[str, str]],
    timeout_seconds: float,
    is_cancelled: Callable[[], bool] | None = None,
) -> EngineResult:
    """Evaluate ``rules`` against one case in order (spec 04 section 2).

    The connection is used as-is: the caller supplies the case's detection
    read connection; this registers the UDFs on it and installs (and always
    removes) the per-rule progress handler. Each rule gets exactly one
    :class:`RuleExecution` - errors and timeouts are outcomes, not
    exceptions - except correlation rules, which raise because the
    correlation stage owns them.

    ``is_cancelled`` is polled between rules; when it turns true the pass
    stops and ``EngineResult.cancelled`` is set with the rules evaluated so
    far.
    """
    register_udfs(connection)
    executions: list[RuleExecution] = []
    for record in rules:
        if is_cancelled is not None and is_cancelled():
            return EngineResult(tuple(executions), cancelled=True)
        if record.rule_type == RULE_TYPE_CORRELATION:
            raise ValueError("correlation rules run in the correlation stage, not here")
        executions.append(
            _execute_one(
                connection,
                case_id=case_id,
                record=record,
                logsource_map=logsource_map,
                timeout_seconds=timeout_seconds,
            )
        )
    return EngineResult(tuple(executions), cancelled=False)


def _execute_one(
    connection: sqlite3.Connection,
    *,
    case_id: str,
    record: RuleRecord,
    logsource_map: dict[str, dict[str, str]],
    timeout_seconds: float,
) -> RuleExecution:
    started = time.monotonic()
    deadline = started + timeout_seconds

    def _progress() -> int:
        return 1 if time.monotonic() >= deadline else 0

    def _finish(
        status: str,
        *,
        matches: tuple[EventMatch, ...] = (),
        error: str | None = None,
    ) -> RuleExecution:
        duration_ms = int((time.monotonic() - started) * 1000)
        return RuleExecution(
            RuleOutcome(record.id, status, len(matches), duration_ms, error),
            matches,
        )

    connection.set_progress_handler(_progress, _PROGRESS_STEPS)
    try:
        evaluated = _evaluate(
            connection,
            case_id=case_id,
            record=record,
            logsource_map=logsource_map,
        )
    except CompileError as exc:
        return _finish(RULE_RUN_ERROR, error=str(exc))
    except sqlite3.OperationalError as exc:
        if "interrupt" in str(exc).lower():
            return _finish(RULE_RUN_TIMEOUT, error=f"rule exceeded its {timeout_seconds:g}s budget")
        return _finish(RULE_RUN_ERROR, error=f"{type(exc).__name__}: {exc}")
    except Exception as exc:
        return _finish(RULE_RUN_ERROR, error=f"{type(exc).__name__}: {exc}")
    finally:
        connection.set_progress_handler(None, 0)

    if isinstance(evaluated, _Skipped):
        return _finish(evaluated.status, error=evaluated.error)
    warning = f"field_never_present: {', '.join(evaluated.missing)}" if evaluated.missing else None
    return _finish(RULE_RUN_OK, matches=evaluated.matches, error=warning)


def _evaluate(
    connection: sqlite3.Connection,
    *,
    case_id: str,
    record: RuleRecord,
    logsource_map: dict[str, dict[str, str]],
) -> _Skipped | _Evaluated:
    """Prepare, prune, compile, probe presence and fetch (spec 04 section 2).

    Raises:
        CompileError: when pySigma cannot convert an otherwise healthy rule.
        sqlite3.OperationalError: on budget abort (``interrupted``) or any
            other query failure - the caller turns both into outcomes.
    """
    prepared = _prepare(record, logsource_map)
    if isinstance(prepared, _Skipped):
        return prepared
    if not _has_inventory(connection, case_id=case_id, route=prepared.route):
        return _Skipped(RULE_RUN_SKIPPED_NO_DATA, None)
    compiled = compile_detection(prepared.sigma_rule)
    if compiled is None:  # pragma: no cover - correlations never reach here
        return _Skipped(RULE_RUN_ERROR, "rule compiles to no detection")
    missing = _never_present(
        connection, case_id=case_id, route=prepared.route, rule=prepared.sigma_rule
    )
    rows = _fetch_matches(connection, case_id=case_id, route=prepared.route, compiled=compiled)
    matches = tuple(
        EventMatch(int(row["id"]), row["ts_ms"], row["host"], row["user_name"]) for row in rows
    )
    return _Evaluated(matches=matches, missing=tuple(missing))


def _prepare(record: RuleRecord, logsource_map: dict[str, dict[str, str]]) -> _Prepared | _Skipped:
    """Catalogue short-circuit, parse, fence and route; never executes SQL.

    Order follows spec 04 section 2: a rule that cannot compile or route is
    an outcome with the reason, before any data is touched.
    """
    if record.compile_error is not None:
        return _Skipped(RULE_RUN_ERROR, record.compile_error)
    sigma_rule = _parse(record)
    if isinstance(sigma_rule, _Skipped):
        return sigma_rule
    rejected = _regexp_problems(sigma_rule)
    if rejected:
        return _Skipped(RULE_RUN_ERROR, "regexp rejected " + "; ".join(rejected))
    route = build_route(
        logsource_map,
        _logsource_value(record.logsource, "product"),
        _logsource_value(record.logsource, "service"),
        _logsource_value(record.logsource, "category"),
    )
    if isinstance(route, Unroutable):
        return _Skipped(RULE_RUN_ERROR, f"unroutable: {route.reason}")
    return _Prepared(sigma_rule=sigma_rule, route=route)


def _parse(record: RuleRecord) -> SigmaRule | _Skipped:
    """Parse the stored YAML to a Sigma rule, or explain why it cannot."""
    try:
        document = yaml.safe_load(record.yaml)
    except Exception as exc:
        return _Skipped(RULE_RUN_ERROR, f"cannot parse rule: {_describe(exc)}")
    if not isinstance(document, dict):
        return _Skipped(RULE_RUN_ERROR, "cannot parse rule: rule document is not a mapping")
    try:
        return SigmaRule.from_dict(document)
    except Exception as exc:
        return _Skipped(RULE_RUN_ERROR, f"cannot parse rule: {_describe(exc)}")


def _has_inventory(connection: sqlite3.Connection, *, case_id: str, route: Route) -> bool:
    """True when any source in the case has an inventory row on the route.

    The case scope rides in a subquery rather than a join: ``sources`` also
    has a ``log_type`` column, so joining it would make every bare route
    column ambiguous. Inside ``source_inventory`` alone the route's columns
    resolve unambiguously (the map only ever references shared names).
    """
    row = connection.execute(
        "SELECT 1 FROM source_inventory "
        f"WHERE ({route.sql}) "
        "AND source_id IN (SELECT id FROM sources WHERE case_id = ?) "
        "LIMIT 1",
        (case_id,),
    ).fetchone()
    return row is not None


def _never_present(
    connection: sqlite3.Connection, *, case_id: str, route: Route, rule: SigmaRule
) -> list[str]:
    """Rule-spelling field names absent from every routed event (spec 04 4).

    One aggregate scan: ``MAX(<expr> IS NOT NULL)`` is 0 only when no routed
    event carries the field, and NULL only when there are no routed events at
    all - a vacuous absence is not a warning.
    """
    resolver = FieldResolver(FieldContext.from_logsource(rule.logsource))
    names: list[str] = []
    seen: set[str] = set()
    exprs: list[str] = []
    for name in sorted(referenced_fields(rule)):
        resolved = resolver.resolve(name)
        if resolved in seen:
            continue
        seen.add(resolved)
        names.append(name)
        exprs.append(resolver.presence_expression(resolved))
    if not exprs:
        return []
    select = ", ".join(f"MAX({expr})" for expr in exprs)
    row = connection.execute(
        f"SELECT {select} FROM events WHERE case_id = ? AND ({route.sql})",
        (case_id,),
    ).fetchone()
    if row is None:  # pragma: no cover - aggregate without GROUP BY always rows
        return []
    return [name for name, value in zip(names, row, strict=True) if value == 0]


def _fetch_matches(
    connection: sqlite3.Connection, *, case_id: str, route: Route, compiled: CompiledDetection
) -> list[sqlite3.Row]:
    """Run the rule's match query, time-ordered with id tie-breaks."""
    sql = (
        f"SELECT {_MATCH_COLUMNS} FROM events "
        f"WHERE case_id = ? AND ({route.sql}) AND ({compiled.sql}) "
        "ORDER BY ts_ms, id"
    )
    return connection.execute(sql, (case_id,)).fetchall()


def _regexp_problems(rule: SigmaRule) -> list[str]:
    """Fence verdicts for every ``|re`` pattern in ``rule``, as display text.

    Walks the parsed condition tree for :class:`SigmaRegularExpression`
    nodes; each rejected pattern renders ``'<pattern>' (<reason>)`` so the
    outcome names the exact offender (spec 09 D-06).
    """
    problems: list[str] = []
    seen: set[int] = set()
    stack: list[Any] = [condition.parsed for condition in rule.detection.parsed_condition]
    while stack:
        node = stack.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        if isinstance(node, SigmaRegularExpression):
            pattern = str(node.regexp)
            reason = pattern_problem(pattern)
            if reason is not None:
                problems.append(f"{pattern!r} ({reason})")
            continue
        if isinstance(node, (list, tuple)):
            stack.extend(node)
            continue
        for attr in ("args", "value", "expressions", "before", "after"):
            child = getattr(node, attr, None)
            if child is not None:
                stack.append(child)
    return problems


def _logsource_value(logsource: dict[str, Any], key: str) -> str | None:
    value = logsource.get(key)
    return str(value) if value is not None else None


def _describe(exc: Exception) -> str:
    try:
        return str(exc) or exc.__class__.__name__
    except Exception:
        return exc.__class__.__name__


__all__ = [
    "EngineResult",
    "EventMatch",
    "RuleExecution",
    "RuleOutcome",
    "execute_rules",
]
