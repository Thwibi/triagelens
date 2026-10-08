"""Alert construction and recording (spec 04 section 6).

Turns an engine run's matches into alerts: one per ``(rule, host|user)``
per time cluster, with ``alert.id = sha256(case|rule|group_key|cluster_start)[:16]``
so a re-run over the same data lands on the same row and an analyst's status
travels with it.

Clustering splits a group when consecutive matches are separated by *more*
than the group window; a gap of exactly the window still belongs to one
alert. Matches without a timestamp sort first and count as epoch 0 for
clustering, keeping the whole pipeline deterministic.

Recording is one transaction: superseded ``new`` alerts go, every draft is
upserted (carrying any analyst status over), evidence is linked, and only
then are scores computed - the overlap and sibling modifiers need their
peers already in the table.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import replace

import yaml

from app.db.connection import atomic
from app.db.repositories.alerts import AlertRepository
from app.detect.engine import EventMatch, RuleExecution
from app.detect.scoring import base_score, score_alert
from app.models.alert import AlertDraft, AlertRecord
from app.models.rule import RULE_TYPE_CORRELATION, RuleRecord
from app.models.run import RULE_RUN_OK
from app.util.hashing import content_id

#: A match with no timestamp participates as if it happened at the epoch.
_EPOCH_MS = 0


def build_alerts(
    *,
    case_id: str,
    run_id: str,
    rules: Mapping[str, RuleRecord],
    executions: Sequence[RuleExecution],
    window_minutes: int,
    max_sample_events: int,
) -> list[AlertDraft]:
    """Group engine matches into alert drafts (spec 04 section 6).

    ``rules`` must hold a record for every executed rule; correlation rules
    are skipped because the correlation stage owns their alerts (spec 04
    section 5). Draft order is deterministic: rule order, then group key,
    then time.
    """
    window_ms = window_minutes * 60 * 1000
    drafts: list[AlertDraft] = []
    for execution in executions:
        record = rules.get(execution.outcome.rule_id)
        if record is None:
            raise ValueError(f"unknown rule in execution: {execution.outcome.rule_id!r}")
        if record.rule_type == RULE_TYPE_CORRELATION:
            continue
        if execution.outcome.status != RULE_RUN_OK or not execution.matches:
            continue
        false_positives = _yaml_list(record.yaml, "falsepositives")
        references = _yaml_list(record.yaml, "references")
        for group_key, matches in sorted(_group_by_key(execution.matches).items()):
            for cluster in _clusters(matches, window_ms):
                first = cluster[0]
                last = cluster[-1]
                start_ms = _effective_ms(first)
                drafts.append(
                    AlertDraft(
                        id=content_id(case_id, record.id, group_key, str(start_ms)),
                        case_id=case_id,
                        run_id=run_id,
                        rule_id=record.id,
                        rule_title=record.title,
                        rule_kind=record.kind,
                        rule_type=record.rule_type,
                        level=record.level,
                        host=first.host,
                        user_name=first.user_name,
                        group_key=group_key,
                        first_seen_ms=start_ms,
                        last_seen_ms=_effective_ms(last),
                        match_count=len(cluster),
                        event_ids=tuple(match.event_id for match in cluster[:max_sample_events]),
                        false_positives=false_positives,
                        references=references,
                    )
                )
    return drafts


def record_alerts(
    connection: sqlite3.Connection,
    *,
    case_id: str,
    run_id: str,
    rules: Mapping[str, RuleRecord],
    executions: Sequence[RuleExecution],
    window_minutes: int,
    max_sample_events: int,
) -> list[AlertRecord]:
    """Build, persist and score this run's alerts in one transaction.

    Returns the persisted records with their final scores. Score breakdowns
    are intentionally not stored: the alert detail endpoint recomputes them
    from the same stored state (spec 04 section 8).
    """
    drafts = build_alerts(
        case_id=case_id,
        run_id=run_id,
        rules=rules,
        executions=executions,
        window_minutes=window_minutes,
        max_sample_events=max_sample_events,
    )
    repository = AlertRepository(connection)
    with atomic(connection):
        repository.clear_previous_new(case_id, run_id)
        records = [_persist(repository, draft) for draft in drafts]
        scored: list[AlertRecord] = []
        for record in records:
            rule = rules[record.rule_id]
            result = score_alert(connection, record, rule_status=rule.status)
            repository.set_score(record.id, result.score)
            scored.append(replace(record, score=result.score))
    return scored


def _persist(repository: AlertRepository, draft: AlertDraft) -> AlertRecord:
    """Upsert one draft with its base score and link its evidence sample."""
    record = repository.upsert(draft, score=base_score(draft.level))
    repository.link_events(draft.id, draft.event_ids)
    return record


def _group_by_key(matches: Sequence[EventMatch]) -> dict[str, list[EventMatch]]:
    """Bucket matches by ``host|user_name`` (empty parts for ``None``)."""
    groups: dict[str, list[EventMatch]] = {}
    for match in matches:
        key = f"{match.host or ''}|{match.user_name or ''}"
        groups.setdefault(key, []).append(match)
    return groups


def _clusters(matches: Sequence[EventMatch], window_ms: int) -> list[list[EventMatch]]:
    """Split one group into time clusters (spec 04 section 6).

    Matches are ordered by timestamp (then event id); a gap of more than
    ``window_ms`` between consecutive matches starts a new cluster.
    """
    ordered = sorted(matches, key=lambda match: (_effective_ms(match), match.event_id))
    clusters: list[list[EventMatch]] = [[ordered[0]]]
    previous_ms = _effective_ms(ordered[0])
    for match in ordered[1:]:
        current_ms = _effective_ms(match)
        if current_ms - previous_ms > window_ms:
            clusters.append([])
        clusters[-1].append(match)
        previous_ms = current_ms
    return clusters


def _effective_ms(match: EventMatch) -> int:
    """The match's timestamp for ordering, clustering and ids."""
    return _EPOCH_MS if match.ts_ms is None else match.ts_ms


def _yaml_list(yaml_text: str, key: str) -> tuple[str, ...]:
    """A rule's ``falsepositives``/``references`` list, in document order.

    The rule loader already parsed this document once, so a failure here
    means the text changed underneath us; the alert then simply carries no
    list rather than failing the run.
    """
    try:
        document = yaml.safe_load(yaml_text)
    except yaml.YAMLError:
        return ()
    if not isinstance(document, dict):
        return ()
    raw = document.get(key)
    if isinstance(raw, str):
        return (raw,)
    if not isinstance(raw, list):
        return ()
    return tuple(str(item) for item in raw if item is not None)


__all__ = ["build_alerts", "record_alerts"]
