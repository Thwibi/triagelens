"""Correlation stage (spec 04 section 5).

Sigma correlation rules (``event_count``, ``value_count``, ``temporal``,
``temporal_ordered``) run after the base engine pass, in Python over the base
rules' matches. Each referenced base rule contributes one SQL fetch per
correlation that names it, selecting the ``group-by`` values (and the
``condition.field`` value for ``value_count``) resolved through the *base*
rule's logsource - which is how ``group-by: [IpAddress]`` on a Windows rule
and ``group-by: [src_ip]`` on a Linux rule group the same logical field (the
spec's "aliases honored").

Windows are end-anchored and closed on both sides: an event exactly
``timespan`` milliseconds after the window's last event still belongs to it.
Windows whose evidence overlaps (touching counts) are coalesced into one
firing per group; a firing's ``first_seen`` is the earliest evidence event of
the first window, ``last_seen`` the latest of the last (spec 04 section 5).

A correlation may reference another correlation (nested, spec 09 D-07): the
child's firing windows each contribute one synthetic row, timestamped at the
child's last evidence event, and the parent resolves its group-by fields
against the child's group-by names (raw spelling first, then resolved
column). Chains deeper than three correlations and reference cycles are
rejected with error outcomes, never exceptions.

``generate`` (an engine convention inside the correlation block, default
false) decides whether a base rule referenced by correlations also produces
its own alerts:
:func:`bases_suppressed_by_correlations` reports the bases that only ever
feed correlations, so the run's alert layer can skip them (spec 04
section 5 step 4).

Every correlation rule gets exactly one :class:`RuleExecution` - parse and
reference failures are outcomes, not exceptions - mirroring the base engine.
"""

from __future__ import annotations

import sqlite3
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass

import yaml
from sigma.rule import SigmaRule

from app.detect.alerts import build_alerts, record_drafts, yaml_list
from app.detect.compile import CompileError, compile_detection
from app.detect.engine import EventMatch, RuleExecution, RuleOutcome
from app.detect.fields import FieldContext, FieldResolver
from app.detect.routing import Unroutable, build_route
from app.models.alert import AlertDraft, AlertRecord
from app.models.rule import RULE_TYPE_CORRELATION, RULE_TYPE_DETECTION, RuleRecord
from app.models.run import RULE_RUN_ERROR, RULE_RUN_OK, RULE_RUN_SKIPPED_NO_DATA
from app.util.hashing import content_id

#: The deepest ``rules:`` chain of correlation references that still
#: evaluates (spec 04 section 5 step 1; deeper nesting errors out).
_MAX_DEPTH = 3

#: A match with no timestamp participates as if it happened at the epoch -
#: the same convention the base alert clustering uses (spec 04 section 6).
_EPOCH_MS = 0

#: Timespan suffixes a correlation document may use, in milliseconds.
_TIMESPAN_UNITS = {"s": 1_000, "m": 60_000, "h": 3_600_000, "d": 86_400_000}

_THRESHOLD_OPERATORS = {
    "gte": lambda value, threshold: value >= threshold,
    "gt": lambda value, threshold: value > threshold,
    "lte": lambda value, threshold: value <= threshold,
    "lt": lambda value, threshold: value < threshold,
    "eq": lambda value, threshold: value == threshold,
}


@dataclass(frozen=True, slots=True)
class CorrelationFiring:
    """One coalesced firing of one correlation rule for one group."""

    rule_id: str
    #: The ``group-by`` values, in declared order (``None`` for absent).
    group_values: tuple[str | None, ...]
    #: The values joined with ``|`` - the alert layer's group key.
    group_key: str
    #: The contributing events, time-ordered and de-duplicated by event id.
    matches: tuple[EventMatch, ...]


@dataclass(frozen=True, slots=True)
class CorrelationResult:
    """Everything the correlation stage evaluated, in evaluation order."""

    executions: tuple[RuleExecution, ...]
    firings: tuple[CorrelationFiring, ...]
    cancelled: bool


@dataclass(frozen=True, slots=True)
class _Definition:
    """A correlation document's ``correlation:`` block, parsed and checked."""

    corr_type: str
    refs: tuple[str, ...]
    group_by: tuple[str, ...]
    timespan_ms: int
    threshold: int | None
    operator: str | None
    condition_field: str | None
    generate: bool


@dataclass(frozen=True, slots=True)
class _Resolved:
    """A definition whose refs are resolved to rule ids, in order."""

    rule_id: str
    definition: _Definition
    ref_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _Row:
    """One match row: a leaf event or a synthetic child-firing row."""

    ref_id: str
    event_id: int
    ts_ms: int
    host: str | None
    user_name: str | None
    #: Group values aligned with the asking correlation's ``group-by``.
    groups: tuple[str | None, ...]
    #: The ``condition.field`` value, for ``value_count`` only.
    value: str | None


@dataclass(frozen=True, slots=True)
class _Window:
    """One qualifying sliding window, before coalescing."""

    start_ms: int
    end_ms: int
    rows: tuple[_Row, ...]


@dataclass(frozen=True, slots=True)
class _Eval:
    """What evaluating one correlation produced."""

    status: str
    windows: tuple[_Window, ...]
    error: str | None = None


class _DefinitionError(Exception):
    """The correlation document itself is malformed."""


class _AbortError(Exception):
    """A reference or resolution failure that becomes an error outcome."""


def execute_correlations(
    connection: sqlite3.Connection,
    *,
    case_id: str,
    rules: Sequence[RuleRecord],
    catalogue: Sequence[RuleRecord],
    base_executions: Mapping[str, RuleExecution],
    logsource_map: dict[str, dict[str, str]],
    is_cancelled: Callable[[], bool] | None = None,
) -> CorrelationResult:
    """Evaluate ``rules`` (correlation rules only) against one case.

    ``catalogue`` is the run's full rule set - the reference index resolves
    ``rules:`` entries by id or by title against it. ``base_executions`` is
    the base engine pass of the *same* run, keyed by rule id: a referenced
    base rule that did not run there makes the correlation an error outcome.

    Each rule gets exactly one :class:`RuleExecution`; its firings ride
    along for the alert layer. ``is_cancelled`` is polled between rules.
    """
    stage = _Stage(
        connection,
        case_id=case_id,
        catalogue=catalogue,
        base_executions=base_executions,
        logsource_map=logsource_map,
    )
    executions: list[RuleExecution] = []
    firings: list[CorrelationFiring] = []
    for record in rules:
        if record.rule_type != RULE_TYPE_CORRELATION:
            raise ValueError("only correlation rules run in the correlation stage")
        if is_cancelled is not None and is_cancelled():
            return CorrelationResult(tuple(executions), tuple(firings), cancelled=True)
        execution, rule_firings = stage.run_one(record)
        executions.append(execution)
        firings.extend(rule_firings)
    return CorrelationResult(tuple(executions), tuple(firings), cancelled=False)


def build_firing_drafts(
    *,
    case_id: str,
    run_id: str,
    rules: Mapping[str, RuleRecord],
    firings: Sequence[CorrelationFiring],
    max_sample_events: int,
) -> list[AlertDraft]:
    """Turn correlation firings into alert drafts (spec 04 section 5 step 5).

    One draft per firing: the group key is the firing's group-by values
    joined with ``|`` (one alert per spray source, not per victim account),
    evidence is the contributing events capped at ``max_sample_events``, and
    the id follows the same deterministic formula as base alerts.
    """
    drafts: list[AlertDraft] = []
    for firing in firings:
        record = rules.get(firing.rule_id)
        if record is None:
            raise ValueError(f"unknown rule in firing: {firing.rule_id!r}")
        if not firing.matches:
            continue
        first = firing.matches[0]
        last = firing.matches[-1]
        start_ms = first.ts_ms if first.ts_ms is not None else _EPOCH_MS
        drafts.append(
            AlertDraft(
                id=content_id(case_id, record.id, firing.group_key, str(start_ms)),
                case_id=case_id,
                run_id=run_id,
                rule_id=record.id,
                rule_title=record.title,
                rule_kind=record.kind,
                rule_type=record.rule_type,
                level=record.level,
                host=first.host,
                user_name=first.user_name,
                group_key=firing.group_key,
                first_seen_ms=start_ms,
                last_seen_ms=last.ts_ms if last.ts_ms is not None else _EPOCH_MS,
                match_count=len(firing.matches),
                event_ids=tuple(match.event_id for match in firing.matches[:max_sample_events]),
                false_positives=yaml_list(record.yaml, "falsepositives"),
                references=yaml_list(record.yaml, "references"),
            )
        )
    return drafts


def run_drafts(
    *,
    case_id: str,
    run_id: str,
    rules: Mapping[str, RuleRecord],
    base_executions: Sequence[RuleExecution],
    correlation_result: CorrelationResult,
    window_minutes: int,
    max_sample_events: int,
) -> list[AlertDraft]:
    """Every alert draft one complete run produces (spec 04 sections 5, 6).

    Base alerts, minus the base rules that only feed correlations with
    ``generate: false``, plus one draft per correlation firing.
    """
    suppressed = bases_suppressed_by_correlations(rules.values())
    kept = [
        execution for execution in base_executions if execution.outcome.rule_id not in suppressed
    ]
    drafts = build_alerts(
        case_id=case_id,
        run_id=run_id,
        rules=rules,
        executions=kept,
        window_minutes=window_minutes,
        max_sample_events=max_sample_events,
    )
    drafts.extend(
        build_firing_drafts(
            case_id=case_id,
            run_id=run_id,
            rules=rules,
            firings=correlation_result.firings,
            max_sample_events=max_sample_events,
        )
    )
    return drafts


def record_run_alerts(
    connection: sqlite3.Connection,
    *,
    case_id: str,
    run_id: str,
    rules: Mapping[str, RuleRecord],
    base_executions: Sequence[RuleExecution],
    correlation_result: CorrelationResult,
    window_minutes: int,
    max_sample_events: int,
) -> list[AlertRecord]:
    """Build, persist and score a complete run's alerts in one transaction."""
    drafts = run_drafts(
        case_id=case_id,
        run_id=run_id,
        rules=rules,
        base_executions=base_executions,
        correlation_result=correlation_result,
        window_minutes=window_minutes,
        max_sample_events=max_sample_events,
    )
    return record_drafts(
        connection,
        case_id=case_id,
        run_id=run_id,
        rules=rules,
        drafts=drafts,
    )


def bases_suppressed_by_correlations(rules: Iterable[RuleRecord]) -> set[str]:
    """Base rule ids referenced only with ``generate`` not true (spec 04 5.4).

    A base that any referencing correlation marks ``generate: true`` alerts
    on its own; one referenced only by ``generate: false`` (the default)
    correlations feeds them and stays silent. Unresolvable references and
    malformed documents simply do not suppress anything.
    """
    index = _index_by_ref(rules)
    referenced: dict[str, list[bool]] = {}
    for record in rules:
        if record.rule_type != RULE_TYPE_CORRELATION:
            continue
        try:
            definition = _parse_definition(record)
        except _DefinitionError:
            continue
        for ref in definition.refs:
            target = _lookup(index, ref)
            if target is None or target.rule_type != RULE_TYPE_DETECTION:
                continue
            referenced.setdefault(target.id, []).append(definition.generate)
    return {rule_id for rule_id, flags in referenced.items() if not any(flags)}


class _Stage:
    """One correlation pass: reference index, leaf-row cache, evaluations."""

    __slots__ = ("_base", "_case_id", "_conn", "_index", "_leaf_cache", "_map")

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        case_id: str,
        catalogue: Sequence[RuleRecord],
        base_executions: Mapping[str, RuleExecution],
        logsource_map: dict[str, dict[str, str]],
    ) -> None:
        self._conn = connection
        self._case_id = case_id
        self._index = _index_by_ref(catalogue)
        self._base = base_executions
        self._map = logsource_map
        self._leaf_cache: dict[tuple[str, str], list[_Row]] = {}

    def run_one(self, record: RuleRecord) -> tuple[RuleExecution, list[CorrelationFiring]]:
        """One correlation rule: outcome plus its firings, never an exception."""
        started = time.monotonic()

        def _finish(
            status: str,
            windows: Sequence[_Window] = (),
            *,
            error: str | None = None,
        ) -> tuple[RuleExecution, list[CorrelationFiring]]:
            duration_ms = int((time.monotonic() - started) * 1000)
            firings = [self._to_firing(record, window) for window in windows]
            match_count = sum(len(firing.matches) for firing in firings)
            outcome = RuleOutcome(record.id, status, match_count, duration_ms, error)
            events = tuple(match for firing in firings for match in firing.matches)
            return RuleExecution(outcome, events), firings

        try:
            definition = _parse_definition(record)
            resolved = self._resolve(record, definition)
        except (_DefinitionError, _AbortError) as exc:
            return _finish(RULE_RUN_ERROR, error=str(exc))
        try:
            evaluated = self._eval(resolved, depth=1, stack=frozenset({record.id}))
        except _AbortError as exc:
            return _finish(RULE_RUN_ERROR, error=str(exc))
        if evaluated.status == RULE_RUN_ERROR:
            return _finish(RULE_RUN_ERROR, error=evaluated.error)
        return _finish(evaluated.status, evaluated.windows)

    def _resolve(self, record: RuleRecord, definition: _Definition) -> _Resolved:
        """Resolve every ref to a rule id; unknown refs abort the rule."""
        ref_ids: list[str] = []
        for ref in definition.refs:
            target = _lookup(self._index, ref)
            if target is None:
                raise _AbortError(f"unknown rule reference: {ref!r}")
            if target.id not in ref_ids:
                ref_ids.append(target.id)
        return _Resolved(rule_id=record.id, definition=definition, ref_ids=tuple(ref_ids))

    def _eval(self, resolved: _Resolved, *, depth: int, stack: frozenset[str]) -> _Eval:
        """Evaluate one correlation, expanding nested references recursively."""
        if depth > _MAX_DEPTH:
            raise _AbortError(f"correlation nesting deeper than {_MAX_DEPTH} levels")
        definition = resolved.definition
        rows: list[_Row] = []
        saw_ref = False
        all_refs_empty = True
        for ref_id in resolved.ref_ids:
            target = self._index[ref_id]
            if target.rule_type == RULE_TYPE_DETECTION:
                saw_ref = True
                leaf = self._leaf_rows(target, definition)
                if leaf is None:  # referenced base rule errored or is missing
                    raise _AbortError(self._leaf_problem(target))
                rows.extend(leaf)
                if leaf:
                    all_refs_empty = False
                continue
            if ref_id in stack:
                raise _AbortError(f"circular correlation reference: {ref_id!r}")
            child = self._resolve(target, _parse_definition(target))
            child_eval = self._eval(child, depth=depth + 1, stack=stack | {ref_id})
            if child_eval.status == RULE_RUN_ERROR:
                raise _AbortError(child_eval.error or "referenced correlation failed")
            saw_ref = True
            child_rows = self._child_rows(child, child_eval.windows, definition)
            rows.extend(child_rows)
            if child_rows:
                all_refs_empty = False
        if saw_ref and all_refs_empty:
            return _Eval(RULE_RUN_SKIPPED_NO_DATA, ())
        windows: list[_Window] = []
        groups: dict[tuple[str | None, ...], list[_Row]] = {}
        for row in rows:
            groups.setdefault(row.groups, []).append(row)
        for group_rows in groups.values():
            windows.extend(self._windows(resolved, group_rows))
        return _Eval(RULE_RUN_OK, tuple(windows))

    def _leaf_rows(self, base: RuleRecord, definition: _Definition) -> list[_Row] | None:
        """The base rule's match rows with this correlation's group columns.

        ``None`` means the reference is unusable (the base did not run, or
        its predicate cannot be derived); see :meth:`_leaf_problem`.
        """
        key = (base.id, _definition_key(definition))
        cached = self._leaf_cache.get(key)
        if cached is not None:
            return cached
        execution = self._base.get(base.id)
        if execution is None:
            return None
        if execution.outcome.status == RULE_RUN_SKIPPED_NO_DATA:
            return []
        if execution.outcome.status != RULE_RUN_OK:
            return None
        predicate = self._predicate(base)
        resolver = FieldResolver(
            FieldContext(
                category=base.logsource.get("category"),
                product=base.logsource.get("product"),
                service=base.logsource.get("service"),
            )
        )
        group_exprs = [resolver.resolve(field) for field in definition.group_by]
        value_expr = (
            resolver.resolve(definition.condition_field)
            if definition.condition_field is not None
            else None
        )
        select = "id, ts_ms, host, user_name"
        if group_exprs:
            select += ", " + ", ".join(group_exprs)
        if value_expr is not None:
            select += f", {value_expr} AS corr_value"
        sql = f"SELECT {select} FROM events WHERE case_id = ? AND {predicate} ORDER BY ts_ms, id"
        rows = [
            self._row(base.id, row, definition, has_value=value_expr is not None)
            for row in self._conn.execute(sql, (self._case_id,)).fetchall()
        ]
        self._leaf_cache[key] = rows
        return rows

    def _row(
        self, ref_id: str, row: sqlite3.Row, definition: _Definition, *, has_value: bool
    ) -> _Row:
        offset = 4  # id, ts_ms, host, user_name
        group_end = offset + len(definition.group_by)
        groups = tuple(_normalize(row[index]) for index in range(offset, group_end))
        value = _normalize(row[group_end]) if has_value else None
        ts = row["ts_ms"]
        return _Row(
            ref_id=ref_id,
            event_id=int(row["id"]),
            ts_ms=_EPOCH_MS if ts is None else int(ts),
            host=row["host"],
            user_name=row["user_name"],
            groups=groups,
            value=value,
        )

    def _leaf_problem(self, base: RuleRecord) -> str:
        """Why ``base`` cannot contribute rows right now."""
        execution = self._base.get(base.id)
        if execution is None:
            return f"referenced base rule {base.id!r} is not part of this run"
        status = execution.outcome.status
        detail = execution.outcome.error
        message = f"referenced base rule {base.id!r} did not run ({status})"
        if detail:
            return f"{message}: {detail}"
        return message

    def _predicate(self, base: RuleRecord) -> str:
        """The base rule's route-and-match SQL, re-derived from its document."""
        try:
            document = yaml.safe_load(base.yaml)
            sigma_rule = SigmaRule.from_dict(document)
        except Exception as exc:
            raise _AbortError(
                f"referenced base rule {base.id!r} cannot parse: {_describe(exc)}"
            ) from exc
        route = build_route(
            self._map,
            base.logsource.get("product"),
            base.logsource.get("service"),
            base.logsource.get("category"),
        )
        if isinstance(route, Unroutable):
            raise _AbortError(f"referenced base rule {base.id!r} is unroutable: {route.reason}")
        try:
            compiled = compile_detection(sigma_rule)
        except CompileError as exc:
            raise _AbortError(f"referenced base rule {base.id!r} cannot compile: {exc}") from exc
        if compiled is None:
            raise _AbortError(f"referenced base rule {base.id!r} compiles to no detection")
        return f"({route.sql}) AND ({compiled.sql})"

    def _child_rows(
        self,
        child: _Resolved,
        windows: Sequence[_Window],
        parent: _Definition,
    ) -> list[_Row]:
        """One synthetic row per child firing, in the parent's group spelling."""
        index_map = tuple(self._child_index(field, child) for field in parent.group_by)
        value_index = (
            self._child_index(parent.condition_field, child)
            if parent.condition_field is not None
            else None
        )
        rows: list[_Row] = []
        for window in windows:
            last = window.rows[-1]
            groups = last.groups
            rows.append(
                _Row(
                    ref_id=child.rule_id,
                    event_id=last.event_id,
                    ts_ms=last.ts_ms,
                    host=last.host,
                    user_name=last.user_name,
                    groups=tuple(groups[index] for index in index_map),
                    value=groups[value_index] if value_index is not None else None,
                )
            )
        return rows

    def _child_index(self, field: str, child: _Resolved) -> int:
        """Where the child stores ``field``: raw spelling, then resolved column.

        Resolution goes through the child's own base rules' logsources, so a
        parent spelling ``IpAddress`` finds the child's ``src_ip`` column when
        both resolve to the same expression. A field neither spelled like a
        child group-by nor resolving to one aborts the parent.
        """
        key = field.strip().casefold()
        for index, child_field in enumerate(child.definition.group_by):
            if child_field.strip().casefold() == key:
                return index
        leaves = [
            self._index[ref_id]
            for ref_id in child.ref_ids
            if self._index[ref_id].rule_type == RULE_TYPE_DETECTION
        ]
        if not leaves:
            raise _AbortError(
                f"cannot resolve field {field!r}: child correlation has no base rules"
            )
        wanted = self._resolve_via(field, leaves[0])
        for index, child_field in enumerate(child.definition.group_by):
            if all(self._resolve_via(child_field, leaf) == wanted for leaf in leaves):
                return index
        raise _AbortError(f"group-by field {field!r} is not produced by the referenced correlation")

    def _resolve_via(self, field: str, leaf: RuleRecord) -> str:
        resolver = FieldResolver(
            FieldContext(
                category=leaf.logsource.get("category"),
                product=leaf.logsource.get("product"),
                service=leaf.logsource.get("service"),
            )
        )
        return resolver.resolve(field)

    def _windows(self, resolved: _Resolved, rows: Sequence[_Row]) -> list[_Window]:
        """End-anchored sliding windows that hold the condition, coalesced."""
        definition = resolved.definition
        ordered = sorted(rows, key=lambda row: (row.ts_ms, row.event_id))
        fired: list[_Window] = []
        left = 0
        for right in range(len(ordered)):
            while ordered[right].ts_ms - ordered[left].ts_ms > definition.timespan_ms:
                left += 1
            window = ordered[left : right + 1]
            if _holds(definition, resolved.ref_ids, window):
                fired.append(
                    _Window(
                        ordered[left].ts_ms,
                        ordered[right].ts_ms,
                        tuple(window),
                    )
                )
        return _coalesce(fired)

    def _to_firing(self, record: RuleRecord, window: _Window) -> CorrelationFiring:
        ordered = sorted(window.rows, key=lambda row: (row.ts_ms, row.event_id))
        seen: set[int] = set()
        matches: list[EventMatch] = []
        for row in ordered:
            if row.event_id in seen:
                continue
            seen.add(row.event_id)
            matches.append(
                EventMatch(
                    event_id=row.event_id,
                    ts_ms=row.ts_ms,
                    host=row.host,
                    user_name=row.user_name,
                )
            )
        groups = ordered[0].groups
        group_key = "|".join("" if value is None else str(value) for value in groups)
        return CorrelationFiring(
            rule_id=record.id,
            group_values=groups,
            group_key=group_key,
            matches=tuple(matches),
        )


def _holds(definition: _Definition, ref_ids: Sequence[str], window: Sequence[_Row]) -> bool:
    """Does this window satisfy the correlation's condition?"""
    if definition.corr_type == "event_count":
        return _compare(len(window), definition)
    if definition.corr_type == "value_count":
        return _compare(len({row.value for row in window}), definition)
    if definition.corr_type == "temporal":
        return set(ref_ids) <= {row.ref_id for row in window}
    # temporal_ordered: the refs must occur in the listed order.
    index = 0
    for row in window:
        if index < len(ref_ids) and row.ref_id == ref_ids[index]:
            index += 1
    return index == len(ref_ids)


def _compare(value: int, definition: _Definition) -> bool:
    operator = definition.operator or "gte"
    threshold = definition.threshold or 0
    return bool(_THRESHOLD_OPERATORS[operator](value, threshold))


def _coalesce(windows: Sequence[_Window]) -> list[_Window]:
    """Merge overlapping or touching windows into one firing per run."""
    merged: list[_Window] = []
    for window in sorted(windows, key=lambda item: (item.start_ms, item.end_ms)):
        if merged and window.start_ms <= merged[-1].end_ms:
            previous = merged[-1]
            merged[-1] = _Window(
                previous.start_ms,
                max(previous.end_ms, window.end_ms),
                _dedupe(previous.rows + window.rows),
            )
        else:
            merged.append(window)
    return merged


def _dedupe(rows: Sequence[_Row]) -> tuple[_Row, ...]:
    seen: set[tuple[str, int]] = set()
    unique: list[_Row] = []
    for row in rows:
        key = (row.ref_id, row.event_id)
        if key in seen:
            continue
        seen.add(key)
        unique.append(row)
    return tuple(unique)


def _normalize(value: object) -> str | None:
    """A group/value cell as text, with NULL kept distinct from empty."""
    return None if value is None else str(value)


def _index_by_ref(rules: Iterable[RuleRecord]) -> dict[str, RuleRecord]:
    """Rule records keyed by id and by case-folded title."""
    index: dict[str, RuleRecord] = {}
    for record in rules:
        index[record.id] = record
        index.setdefault(record.title.casefold(), record)
    return index


def _lookup(index: Mapping[str, RuleRecord], ref: str) -> RuleRecord | None:
    """A ``rules:`` entry by id, then by case-folded title."""
    return index.get(ref) or index.get(ref.casefold())


def _definition_key(definition: _Definition) -> str:
    """A cache key for one correlation's column needs."""
    parts = [definition.corr_type, *definition.group_by]
    if definition.condition_field is not None:
        parts.append(definition.condition_field)
    return "\0".join(parts)


def _parse_definition(record: RuleRecord) -> _Definition:
    """Parse and check a stored correlation document (raises _DefinitionError)."""
    try:
        document = yaml.safe_load(record.yaml)
    except yaml.YAMLError as exc:
        raise _DefinitionError(f"cannot parse rule: {_describe(exc)}") from exc
    if not isinstance(document, dict):
        raise _DefinitionError("cannot parse rule: rule document is not a mapping")
    block = document.get("correlation")
    if not isinstance(block, dict):
        raise _DefinitionError("rule has no correlation block")
    corr_type = str(block.get("type", "")).lower()
    if corr_type not in {"event_count", "value_count", "temporal", "temporal_ordered"}:
        raise _DefinitionError(f"unknown correlation type: {block.get('type')!r}")
    refs = _string_list(block.get("rules"))
    if not refs:
        raise _DefinitionError("correlation lists no rules")
    group_by = _string_list(block.get("group-by"))
    timespan_ms = _parse_timespan(block.get("timespan"))
    threshold: int | None = None
    operator: str | None = None
    condition_field: str | None = None
    if corr_type in {"event_count", "value_count"}:
        threshold, operator = _parse_threshold(block.get("condition"))
        if corr_type == "value_count":
            field = block.get("condition", {})
            raw_field = field.get("field") if isinstance(field, dict) else None
            if not isinstance(raw_field, str) or not raw_field.strip():
                raise _DefinitionError("value_count needs condition.field")
            condition_field = raw_field.strip()
    generate = bool(block.get("generate", False))
    return _Definition(
        corr_type=corr_type,
        refs=refs,
        group_by=group_by,
        timespan_ms=timespan_ms,
        threshold=threshold,
        operator=operator,
        condition_field=condition_field,
        generate=generate,
    )


def _string_list(raw: object) -> tuple[str, ...]:
    if raw is None:
        return ()
    if isinstance(raw, str):
        return (raw,) if raw.strip() else ()
    if isinstance(raw, list):
        return tuple(str(item) for item in raw if item is not None)
    return ()


def _parse_timespan(raw: object) -> int:
    """``10m``-style timespans (or bare seconds) in milliseconds."""
    text = str(raw or "").strip().lower()
    if text.isdigit():
        return int(text) * 1_000
    unit = _TIMESPAN_UNITS.get(text[-1:] if text else "")
    if unit is None or not text[:-1].isdigit():
        raise _DefinitionError(f"cannot parse timespan: {raw!r}")
    return int(text[:-1]) * unit


def _parse_threshold(raw: object) -> tuple[int, str]:
    if not isinstance(raw, dict):
        raise _DefinitionError("condition needs exactly one of gte/gt/lte/lt/eq")
    # ``value_count`` carries ``field`` beside the operator (``{gte: 10,
    # field: TargetUserName``); only the operator participates in the count.
    operators = {key: value for key, value in raw.items() if str(key).lower() != "field"}
    if len(operators) != 1:
        raise _DefinitionError("condition needs exactly one of gte/gt/lte/lt/eq")
    operator, value = next(iter(operators.items()))
    name = str(operator).lower()
    if name not in _THRESHOLD_OPERATORS:
        raise _DefinitionError(f"unknown condition operator: {operator!r}")
    if not isinstance(value, int) or isinstance(value, bool):
        raise _DefinitionError(f"condition threshold must be a number: {value!r}")
    return value, name


def _describe(exc: Exception) -> str:
    try:
        return str(exc) or exc.__class__.__name__
    except Exception:
        return exc.__class__.__name__


__all__ = [
    "CorrelationFiring",
    "CorrelationResult",
    "bases_suppressed_by_correlations",
    "build_firing_drafts",
    "execute_correlations",
    "record_run_alerts",
    "run_drafts",
]
