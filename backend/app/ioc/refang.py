"""Refanging (spec 05 section 2.1).

Defanged indicators are the normal way an analyst pastes a threat report:
``hxxp://evil[.]com/a``. The extractor runs every text value through
:func:`refang` on a **copy** before matching, and keeps the original text as
evidence elsewhere. The replacements only ever turn a defanged spelling back into
its live form; none of them invent a character that was not implied.
"""

from __future__ import annotations

import re

#: Word-for-word replacements, applied before the punctuation ones so ``hxxps``
#: is not half-replaced into ``https`` + a stray ``s``.
_WORD_REPLACEMENTS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"hxxps", re.IGNORECASE), "https"),
    (re.compile(r"hxxp", re.IGNORECASE), "http"),
    (re.compile(r"fxp", re.IGNORECASE), "ftp"),
    (re.compile(r"\[://\]"), "://"),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[@\]|\(at\)|\[at\]", re.IGNORECASE), "@"),
    (re.compile(r"\[dot\]|\(dot\)|\[\.\]|\(\.\)|\{\.\}", re.IGNORECASE), "."),
)

#: `` dot `` between label-like tokens only: ``evil dot com`` but not ``dot product``.
_DOT_WORD = re.compile(r"(?<=[A-Za-z0-9\-]) dot (?=[A-Za-z0-9])", re.IGNORECASE)

#: A backslash-escaped dot inside a domain candidate, ``evil\.com``.
_ESCAPED_DOT = re.compile(r"(?<=[A-Za-z0-9])\\\.(?=[A-Za-z0-9])")


def refang(text: str) -> str:
    """Return ``text`` with defanging conventions reversed.

    The only marker that needs context is `` dot ``: it becomes a dot only
    between label-like tokens, so the English word survives.
    """
    if not text:
        return text
    result = text
    for pattern, replacement in _WORD_REPLACEMENTS:
        result = pattern.sub(replacement, result)
    result = _DOT_WORD.sub(".", result)
    return _ESCAPED_DOT.sub(".", result)


def defang(value: str) -> str:
    """Render a live indicator safe to display or paste (spec 05 section 8).

    ``http`` -> ``hxxp``, dots -> ``[.]``, ``@`` -> ``[@]``. Applied to exports
    when ``defang=true`` and to the UI copy, never to the stored value.
    """
    if not value:
        return value
    result = value.replace("http", "hxxp").replace("HTTP", "hxxp")
    result = result.replace("@", "[@]")
    return result.replace(".", "[.]")


__all__ = ["defang", "refang"]
