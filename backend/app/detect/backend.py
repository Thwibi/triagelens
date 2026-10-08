"""The TriageLens Sigma-to-SQL backend (spec 04 section 2).

Subclasses ``pysigma-backend-sqlite``'s ``sqliteBackend`` and bends it to the
normalized schema:

* **field resolution**: every produced field expression runs through
  :class:`app.detect.fields.FieldResolver`, so ``CommandLine`` and
  ``json_extract(fields_json, '$."TargetUserName"')`` both compile to the same
  store the parsers write.
* **keyword searches**: the stock backend refuses field-less strings (FTS-only);
  TriageLens compiles them to a case-insensitive ``contains`` over the keyword
  columns ``message``, ``process_cmdline``, ``url``, ``raw`` (spec 04 section 2).
* **CIDR**: instead of expanding a network into a potentially hundreds-entry OR
  list, a single ``cidr_match(<field>, '<network>')`` call is emitted and
  satisfied by the SQLite user function.
* **numeric text matching**: ``|contains``-style modifiers on numeric columns
  cast the column to text (spec 04 section 4).
* **firewall action**: ``action: deny``-style Sigma compares against the
  derived ``event_action`` values the parsers write.
"""

from __future__ import annotations

from typing import Any, ClassVar, cast

from sigma.backends.sqlite.sqlite import sqliteBackend
from sigma.conditions import (
    ConditionFieldEqualsValueExpression,
    ConditionValueExpression,
)
from sigma.conversion.state import ConversionState
from sigma.exceptions import SigmaValueError
from sigma.types import (
    SigmaCIDRExpression,
    SigmaString,
)

from app.detect.fields import (
    FIREWALL_ACTION_MAP,
    FieldResolver,
)

#: Columns an unbound Sigma string searches (spec 04 section 2).
KEYWORD_COLUMNS: tuple[str, ...] = ("message", "process_cmdline", "url", "raw")


class TriageBackend(sqliteBackend):
    """SQLite backend bound to TriageLens' normalized event table."""

    # The base class declares an instance ``table``; ``TABLE`` is named
    # distinctly so subclassing does not trigger a variable-override error,
    # and ``resolve_table`` returns it.
    TABLE: ClassVar[str] = "events"

    def __init__(self, **options: Any) -> None:
        super().__init__(**options)  # type: ignore[no-untyped-call]
        self._resolver: FieldResolver | None = None
        self._as_text = False

    def set_field_resolver(self, resolver: FieldResolver) -> None:
        """Bind the resolver used for every subsequent conversion."""
        self._resolver = resolver

    # -- field and table emission -------------------------------------------

    def resolve_table(self, _state: ConversionState | None = None) -> str:
        """The events table, never JSON-escaped or quoted."""
        return self.TABLE

    def escape_and_quote_field(self, field: str) -> str:
        """Route every field through the resolver; cap with CAST only for
        text matching on numeric columns."""
        if self._resolver is not None:
            expression = self._resolver.resolve(field)
            if self._as_text and self._resolver.is_numeric_field(field):
                return f"CAST({expression} AS TEXT)"
            return expression
        resolved = super().escape_and_quote_field(  # type: ignore[no-untyped-call]
            field
        )
        return cast(str, resolved)

    # -- keyword (field-less) searches --------------------------------------

    def convert_condition_val_str(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> str:
        """A field-less string becomes a contains match on the keyword columns."""
        return self._keyword_expression(SigmaString(str(cond.value)), state)

    def convert_condition_val_num(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> str:
        """A field-less number becomes a contains match on the keyword columns."""
        return self._keyword_expression(SigmaString(str(cond.value)), state)

    def _keyword_expression(self, value: SigmaString, state: ConversionState) -> str:
        # ``convert_value_str`` maps Sigma wildcards to LIKE's ``%``/``_`` and
        # escapes a literal ``%``/``_`` the rule text carries. Wrapping the
        # escaped literal with raw ``%`` yields the contains semantics a
        # field-less search means (spec 04 section 2, keyword searches).
        raw = self.convert_value_str(value, state, no_quote=True)
        parts = [
            self.contains_expression.format(field=self.escape_and_quote_field(column), value=raw)
            for column in KEYWORD_COLUMNS
        ]
        return "(" + " OR ".join(parts) + ")"

    # -- CIDR ----------------------------------------------------------------

    def convert_condition_field_eq_val_cidr(
        self, cond: ConditionFieldEqualsValueExpression, _state: ConversionState
    ) -> str:
        """Emit ``cidr_match(<field>, '<network>')`` instead of an OR explosion."""
        if not isinstance(cond.value, SigmaCIDRExpression):
            raise SigmaValueError("cidr modifier requires a network literal")
        escaped = str(cond.value.cidr).replace("'", "''")
        return f"cidr_match({self.escape_and_quote_field(cond.field)}, '{escaped}')"

    # -- text matching with numeric cast / firewall action -------------------

    def convert_condition_field_eq_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
        if (
            self._resolver
            and self._resolver.uses_firewall_action
            and cond.field
            and (cond.field.lower() == "action")
        ):
            return self._firewall_action_expression(cond, state)
        self._as_text = True
        try:
            converted = super().convert_condition_field_eq_val_str(cond, state)
        finally:
            self._as_text = False
        return converted if isinstance(converted, str) else str(converted)

    def convert_condition_field_eq_val_str_case_sensitive(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
        self._as_text = True
        try:
            converted = super().convert_condition_field_eq_val_str_case_sensitive(cond, state)
        finally:
            self._as_text = False
        return converted if isinstance(converted, str) else str(converted)

    def _firewall_action_expression(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
        value = str(cond.value)
        mapped = FIREWALL_ACTION_MAP.get(value.lower())
        if mapped is None:
            mapped = value
        return self.convert_condition_field_eq_val_str(
            ConditionFieldEqualsValueExpression("event_action", SigmaString(mapped)),
            state,
        )


__all__ = ["KEYWORD_COLUMNS", "TriageBackend"]
