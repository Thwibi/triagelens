"""Bundled, pure-Python EVTX reader (vendored).

python-evtx 0.8.1 (https://github.com/williballenthin/python-evtx, Apache-2.0)
is the spec 03 section 2.1 "documented fallback" reader, vendored here so the
``windows_evtx`` parser keeps working where the preferred native backend
(pyevtx-rs, the ``evtx`` package) cannot load: the offline bundle is pure-wheel,
and hardened Windows hosts block native extensions via Application Control.

The upstream package is unmodified except for two mechanical edits recorded
below. ``Views.py`` is kept even though this project renders its own XML, so the
vendored tree stays byte-faithful to upstream.

File provenance (from ``python-evtx==0.8.1``):

- ``Evtx.py``, ``Views.py``, ``Nodes.py``, ``BinaryParser.py``: upstream files.
  Change: the single absolute ``import Evtx.*`` in ``Evtx.py`` and ``Views.py``
  is a relative ``from . import ...``, and ``Nodes.py`` imports the vendored
  ``hexdump`` module relatively.
- ``hexdump.py``: the ``hexdump`` package (MIT), vendored because ``Nodes.py``
  uses it in a string renderer.
- ``__init__.py``: written for this project; upstream exports the same names.
"""

from . import BinaryParser, Evtx, Nodes, Views  # noqa: F401

__all__ = ["Evtx", "BinaryParser", "Nodes", "Views"]