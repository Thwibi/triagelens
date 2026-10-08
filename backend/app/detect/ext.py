"""Small extensions that are required before any Sigma rule parses.

pySigma 1.x knows ``utf16`` (a UTF-16LE string with a BOM) but not the ``utf16le``
alias, while ``utf16le|wide|base64offset`` is one of the most common modifier
combinations in shipped SigmaHQ rules. Rather than meeting every such rule with
``compile_error='unsupported modifier'``, the alias is registered once at first
use. The mapping is exactly the 33-entry table ``modifier_mapping`` builds from
the modifier classes, so registering one more name through the same path keeps
the rest of the parser untouched.
"""

from __future__ import annotations

import threading

from sigma.modifiers import SigmaUTF16Modifier, modifier_mapping

_lock = threading.Lock()
_installed = False


def install_sigma_extensions() -> None:
    """Register the ``utf16le`` modifier alias. Safe to call any number of times."""
    global _installed  # noqa: PLW0603 - process-wide, idempotent install
    with _lock:
        if not _installed:
            modifier_mapping["utf16le"] = SigmaUTF16Modifier
            _installed = True


__all__ = ["install_sigma_extensions"]
