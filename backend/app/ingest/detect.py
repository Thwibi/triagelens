"""Format detection (spec 03 section 1).

Detection answers one question: which parser should read this file? It runs in a
strictly bounded order of trust, because each step is cheaper and more certain
than the next:

1. **An explicit user choice**, which overrides everything.
2. **The filename suffix**, a hint the operator typed.
3. **Magic bytes**, an unambiguous signature such as the ``ElfFile`` header of a
   Windows EVTX file.
4. **A vote among the parsers**, each of which scores the same bounded prefix.

A file that no parser claims is not an error and is not guessed at. It becomes
``needs_input`` carrying the candidates, so the operator picks rather than the
system inventing a format and producing confidently wrong columns.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from app.ingest.parsers.base import Candidate, ParserRegistry, load_builtin_parsers
from app.ingest.text import SNIFF_BYTES, SNIFF_LINES, TextHead, read_head

#: A parser at or above this score claims the file (spec 03 section 1 step 4).
ACCEPT_THRESHOLD = 0.6

#: ...and must beat the runner-up by this much, so a coin flip is not a decision.
DECISION_MARGIN = 0.15

#: Filename suffix to log type. A hint, never a decision on its own.
SUFFIX_MAP: dict[str, str] = {
    ".evtx": "windows_evtx",
    ".xml": "xml",
    ".json": "generic_json",
    ".jsonl": "generic_json",
    ".ndjson": "generic_json",
    ".csv": "generic_csv",
}


@dataclass(frozen=True, slots=True)
class Signature:
    """A byte pattern that identifies a format outright."""

    magic: bytes
    log_type: str
    reason: str
    #: Match case-insensitively, for text formats like XML.
    fold_case: bool = False


#: Hard signatures, checked before any parser is asked.
SIGNATURES: tuple[Signature, ...] = (
    Signature(b"ElfFile\x00", "windows_evtx", "ElfFile magic (Windows EVTX)"),
    Signature(b"<?xml", "xml", "XML declaration", fold_case=True),
    Signature(b"<events", "xml", "<Events> root element", fold_case=True),
)

#: UTF-8 BOM, stripped before a signature is compared so a BOM'd XML still matches.
_UTF8_BOM = b"\xef\xbb\xbf"


@dataclass(slots=True)
class DetectionResult:
    """What detection decided, and what it would have chosen otherwise."""

    #: The log type to parse with, or ``None`` when the operator must choose.
    log_type: str | None
    #: Why that answer: ``override``, ``filename``, ``magic``, ``content`` or ``none``.
    source: str
    #: Every parser that scored, strongest first, for the needs_input list.
    candidates: list[Candidate] = field(default_factory=list)
    #: True when a parser exists for the detected type; False when the format was
    #: recognized but this build cannot parse it yet.
    parser_available: bool = True
    #: Operator-facing explanation, shown when ``needs_input`` is true.
    reason: str = ""

    @property
    def needs_input(self) -> bool:
        """True when no automatic decision can be acted on.

        Two cases, and they need the same handling:

        - The type is unknown, so the operator picks from the candidates.
        - The type was recognized but this build ships no parser for it, so
          picking would not help. The source still goes to ``needs_input``
          rather than a parse job that cannot succeed.
        """
        return self.log_type is None or not self.parser_available

    @property
    def confidence(self) -> float:
        """Score of the accepted candidate, or the best one when undecided."""
        return self.candidates[0].confidence if self.candidates else 0.0

    def as_dict(self) -> dict[str, object]:
        """JSON-ready form for the API."""
        return {
            "log_type": self.log_type,
            "needs_input": self.needs_input,
            "source": self.source,
            "parser_available": self.parser_available,
            "reason": self.reason,
            "candidates": [candidate.as_dict() for candidate in self.candidates],
        }


def detect_suffix(filename: str) -> str | None:
    """The log type a filename suffix suggests, if any."""
    return SUFFIX_MAP.get(Path(filename).suffix.lower())


def match_signature(head: bytes) -> Signature | None:
    """The first hard signature present at the start of ``head``.

    Only a prefix is compared. Scanning the whole head would let a file that
    merely mentions ``<?xml`` in its first 64 KB claim to be XML.
    """
    prefix = head[:_SIGNATURE_SCAN_BYTES]
    if prefix.startswith(_UTF8_BOM):
        prefix = prefix[len(_UTF8_BOM) :]
    for signature in SIGNATURES:
        candidate = signature.magic
        if signature.fold_case:
            if prefix[: len(candidate)].lower() == candidate.lower():
                return signature
        elif prefix.startswith(candidate):
            return signature
    return None


#: How much of the head a magic-number comparison may look at.
_SIGNATURE_SCAN_BYTES = 256


def vote(head: TextHead, registry: ParserRegistry) -> list[Candidate]:
    """Ask every parser to score the head, strongest first.

    Ties are broken by ``log_type`` so the order does not depend on dict or
    import ordering, which would make detection results irreproducible.
    """
    scored = [
        Candidate(
            log_type=parser.log_type,
            confidence=max(0.0, min(1.0, parser.sniff(head))),
            reason="content signature",
        )
        for parser in registry.all()
    ]
    scored.sort(key=lambda item: (-item.confidence, item.log_type))
    return [item for item in scored if item.confidence > 0.0]


def detect(
    path: Path,
    *,
    filename: str | None = None,
    override: str | None = None,
    registry: ParserRegistry | None = None,
) -> DetectionResult:
    """Decide which parser should read ``path``.

    Args:
        path: The file on disk. Detection reads at most :data:`SNIFF_BYTES` of it.
        filename: The uploaded name, used for the suffix hint. Defaults to the
            name on disk.
        override: A log type the operator chose, which wins outright.
        registry: Parsers to choose from; the built-in set by default.
    """
    parsers = registry if registry is not None else load_builtin_parsers()
    display_name = filename if filename is not None else path.name

    if override:
        available = parsers.get(override) is not None
        return DetectionResult(
            log_type=override,
            source="override",
            candidates=[Candidate(override, 1.0, "chosen by the operator")],
            parser_available=available,
            reason="" if available else f"no parser for {override} is available in this build",
        )

    head = read_head(path, max_bytes=SNIFF_BYTES, max_lines=SNIFF_LINES)

    signature = match_signature(head.head)
    if signature is not None:
        available = parsers.get(signature.log_type) is not None
        return DetectionResult(
            log_type=signature.log_type,
            source="magic",
            candidates=[Candidate(signature.log_type, 1.0, signature.reason)],
            parser_available=available,
            reason=""
            if available
            else f"detected {signature.reason}, but no parser for it is available in this build",
        )

    candidates = vote(head, parsers)
    hint = detect_suffix(display_name)
    if hint is not None and all(item.log_type != hint for item in candidates):
        # Surface the filename's suggestion alongside the content's opinion, so
        # the operator sees both when the vote is undecided.
        candidates = [
            Candidate(hint, 0.0, f"filename suffix {Path(display_name).suffix}"),
            *candidates,
        ]

    if not candidates:
        return DetectionResult(
            log_type=None,
            source="none",
            reason="no parser recognized this file; choose a format or supply a mapping profile",
        )

    best = candidates[0]
    scored = [item for item in candidates if item.confidence > 0.0]
    top = scored[0] if scored else best
    runner_up = scored[1].confidence if len(scored) > 1 else 0.0
    decisive = top.confidence >= ACCEPT_THRESHOLD and (
        top.confidence - runner_up >= DECISION_MARGIN
    )
    if decisive:
        available = parsers.get(top.log_type) is not None
        return DetectionResult(
            log_type=top.log_type,
            source="content",
            candidates=candidates,
            parser_available=available,
            reason="" if available else f"no parser for {top.log_type} is available in this build",
        )

    if hint is not None:
        # Undecided content, but the operator named the file deliberately, so
        # the suffix is a better answer than an empty prompt.
        available = parsers.get(hint) is not None
        return DetectionResult(
            log_type=hint,
            source="filename",
            candidates=candidates,
            parser_available=available,
            reason=""
            if available
            else f"filename suggests {hint}, but no parser for it is available in this build",
        )

    reason = (
        f"best guess {top.log_type} scored {top.confidence:.2f}, "
        f"below the {ACCEPT_THRESHOLD:.2f} threshold or not decisive; choose a format"
    )
    return DetectionResult(log_type=None, source="none", candidates=candidates, reason=reason)


def is_binary(head: TextHead) -> bool:
    """True when the head looks binary rather than text.

    Detection reports this so the UI can say "this is a binary file" instead of
    offering a list of text formats for it.
    """
    sample = head.head[:4096]
    if not sample:
        return False
    if sample.startswith((b"\x1f\x8b", b"ElfFile\x00")):
        return True
    control = sum(1 for byte in sample if byte in _TEXT_FORBIDDEN_BYTES)
    return control / len(sample) > _BINARY_CONTROL_SHARE


#: Share of control bytes above which a head is treated as binary.
_BINARY_CONTROL_SHARE = 0.3

#: Byte values that never appear in a text log. Tab, newline and carriage return
#: are excluded because they do; everything else below 0x20 is a control byte, as
#: is DEL. A high share of these means the file is not text.
_TEXT_FORBIDDEN_BYTES = frozenset(range(0x09)) | frozenset(range(0x0E, 0x20)) | {0x7F}


__all__ = [
    "ACCEPT_THRESHOLD",
    "DECISION_MARGIN",
    "SIGNATURES",
    "SUFFIX_MAP",
    "DetectionResult",
    "Signature",
    "detect",
    "detect_suffix",
    "is_binary",
    "match_signature",
    "vote",
]
