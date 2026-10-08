"""Detection engine core (spec 04): routing, fields, compilation, and UDFs.

This package holds everything that turns a Sigma rule into an executable query:

* :mod:`routing` - logsource -> ``events``/``source_inventory`` predicate,
* :mod:`fields` - Sigma field name -> column or ``fields_json`` expression,
* :mod:`backend` - the SQLite backend subclass implementing the mapping,
* :mod:`compile` - whole-rule compilation to a WHERE fragment,
* :mod:`udfs` - ``regexp``/``cidr_match`` used at execution time,
* :mod:`ext` - the one-time pySigma extension install (the ``utf16le`` alias),
* :mod:`rules` - YAML rule loading into the ``rules`` catalogue,
* :mod:`profiles` - which enabled rules a run executes,
* :mod:`engine` - one run: route, prune, compile, execute under budget,
* :mod:`correlation` - Sigma correlation rules over the base matches,
* :mod:`alerts` - match grouping into deterministic, re-run-stable alerts,
* :mod:`scoring` - ``base(level) + modifiers``, clamped to 0-100.

MITRE ATT&CK mapping builds on top of these in the layer above (spec 04
section 7).
"""

from __future__ import annotations

__all__: list[str] = []
