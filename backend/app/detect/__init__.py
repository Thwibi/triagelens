"""Detection engine core (spec 04): routing, fields, compilation, and UDFs.

This package holds everything that turns a Sigma rule into an executable query:

* :mod:`routing` - logsource -> ``events``/``source_inventory`` predicate,
* :mod:`fields` - Sigma field name -> column or ``fields_json`` expression,
* :mod:`backend` - the SQLite backend subclass implementing the mapping,
* :mod:`compile` - whole-rule compilation to a WHERE fragment,
* :mod:`udfs` - ``regexp``/``cidr_match`` used at execution time,
* :mod:`ext` - the one-time pySigma extension install (the ``utf16le`` alias).

Rule loading, scoring, correlation and alert aggregation build on top of these
and live in the rules/engine layer above.
"""

from __future__ import annotations

__all__: list[str] = []
