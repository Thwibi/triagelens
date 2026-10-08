"""Compile a Sigma detection to a TriageLens SQL fragment (spec 04 section 2).

The pipeline for one rule:

1. the rule's logsource becomes a :class:`FieldContext`;
2. :class:`TriageBackend` compiles every parsed condition through pySigma;
3. the finalized queries (``SELECT * FROM events WHERE <expr>``) are unwrapped
   and their ``<expr>`` parts joined with OR - a rule matches when any of its
   parsed conditions matches;
4. every field name the detection references is collected and resolved, so the
   engine can later report ``field_never_present`` warnings (spec 04 section 4).

Correlation rules are never compiled here: they run in Python after their base
rules (spec 04 section 5).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule
from sigma.types import SigmaFieldReference

from app.detect.backend import TriageBackend
from app.detect.ext import install_sigma_extensions
from app.detect.fields import FieldContext, FieldResolver

#: Prefix ``finalize_query_default`` emits; unwrapped so the engine can embed
#: the fragment in its own SELECT.
_FINAL_PREFIX = f"SELECT * FROM {TriageBackend.TABLE} WHERE "


class CompileError(RuntimeError):
    """A rule could not be compiled; ``str`` is the user-facing reason."""


@dataclass(frozen=True, slots=True)
class CompiledDetection:
    """The executable WHERE fragment and the fields it reads.

    ``fields`` holds resolved SQL fragments (column names or ``json_extract``
    calls), used for ``field_never_present`` checks.
    """

    sql: str
    fields: tuple[str, ...]


def compile_detection(rule: SigmaRule | SigmaCorrelationRule) -> CompiledDetection | None:
    """Compile ``rule``; returns ``None`` for correlation rules.

    Raises:
        CompileError: if pySigma cannot convert the rule or the output has an
            unexpected shape.
    """
    if isinstance(rule, SigmaCorrelationRule):
        return None
    sigma_rule: SigmaRule = rule

    install_sigma_extensions()
    resolver = FieldResolver(FieldContext.from_logsource(sigma_rule.logsource))
    backend = TriageBackend(collate_nocase=True)
    backend.set_field_resolver(resolver)

    try:
        final_queries = backend.convert_rule(sigma_rule)  # type: ignore[no-untyped-call]
    except Exception as exc:
        raise CompileError(_describe_error(exc)) from exc

    wheres = _extract_where_parts(final_queries)
    if not wheres:
        raise CompileError("rule has no matching condition")
    compiled = "(" + ") OR (".join(wheres) + ")"

    targets = []
    seen: set[str] = set()
    for field in referenced_fields(sigma_rule):
        resolved = resolver.resolve(field)
        if resolved not in seen:
            seen.add(resolved)
            targets.append(resolved)

    return CompiledDetection(sql=compiled, fields=tuple(targets))


def _extract_where_parts(queries: Iterable[Any]) -> list[str]:
    parts: list[str] = []
    for query in queries:
        if not isinstance(query, str):
            raise CompileError(f"unsupported conversion output {type(query).__name__}")
        if not query.startswith(_FINAL_PREFIX):
            raise CompileError("compiled query has an unexpected shape")
        fragment = query[len(_FINAL_PREFIX) :].strip()
        if not fragment:
            raise CompileError("rule compiles to an empty condition")
        parts.append(fragment)
    return parts


def referenced_fields(rule: SigmaRule) -> set[str]:
    """Every field name the rule's detection references, in rule spelling."""
    fields: set[str] = set()
    stack: list[Any] = [condition.parsed for condition in rule.detection.parsed_condition]
    while stack:
        node = stack.pop()
        field = getattr(node, "field", None)
        if isinstance(field, str) and field:
            fields.add(field)
        value = getattr(node, "value", None)
        if isinstance(value, SigmaFieldReference):
            fields.add(value.field)
        stack.extend(getattr(node, "args", ()))
    return fields


def _describe_error(exc: Exception) -> str:
    try:
        return str(exc) or exc.__class__.__name__
    except Exception:
        return exc.__class__.__name__


__all__ = ["CompileError", "CompiledDetection", "compile_detection", "referenced_fields"]
