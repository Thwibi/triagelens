"""Windows EVTX binary parser (spec 03 section 2).

An EVTX file is a binary event log: a ``FileHeader`` followed by 64 KiB chunks,
each holding binXML records. Two readers can decode it:

* the native ``evtx`` extension (pyevtx-rs), which is fast and the preferred
  path. It emits one JSON record per event, in exactly the ``Event``-wrapped
  shape :func:`app.ingest.parsers.windows_common.map_event_dict` expects.
* the vendored pure-Python ``evtxlib`` reader, used when the native extension is
  not importable (for example an application-control policy blocking its DLL).
  It parses each record into an lxml element, which is converted to the same dict
  shape with :func:`event_dict_from_element`.

Both paths feed the one mapping table, so a column is defined in exactly one
place. A chunk that cannot be decoded is reported as a ``parse_errors`` row and
the remaining chunks are still read, because a single corrupt chunk in a
multi-gigabyte log must not lose the rest of the evidence.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from app.ingest.events import NormalizedEvent
from app.ingest.parsers.base import (
    ParseContext,
    ParseFailure,
    _register,
)
from app.ingest.parsers.windows_common import event_dict_from_element, map_event_dict
from app.ingest.text import TextHead

#: The EVTX file magic, checked before any parsing.
EVTX_MAGIC = b"ElfFile\x00"

try:  # preferred: the native extension
    from evtx import PyEvtxParser as _PyEvtxParser

    _NATIVE_AVAILABLE = True
except (ImportError, OSError):  # DLL load can fail under an application-control policy
    _PyEvtxParser = None  # type: ignore[misc, assignment]
    _NATIVE_AVAILABLE = False

try:  # fallback: the reader vendored into this repository
    from app.ingest.parsers.evtxlib.Evtx import Evtx as _VendoredEvtx
except ImportError:  # pragma: no cover - the vendored reader is always present
    _VendoredEvtx = None  # type: ignore[misc, assignment]


def native_backend_available() -> bool:
    """True when the fast native ``evtx`` extension could be imported."""
    return _PyEvtxParser is not None


class WindowsEvtxParser:
    """Decode EVTX chunks into normalized events."""

    __slots__ = ("_backend",)

    log_type = "windows_evtx"

    def __init__(self, backend: str | None = None) -> None:
        # ``None`` selects the native reader when it imported, else the vendored
        # one. Tests pin ``"vendored"`` so they exercise a reader that is present
        # on every host, including one where the native DLL is blocked.
        self._backend = backend

    def sniff(self, head: TextHead) -> float:
        """1.0 for the ``ElfFile`` magic, 0.0 otherwise."""
        return 1.0 if head.head.startswith(EVTX_MAGIC) else 0.0

    def parse(self, context: ParseContext) -> Iterator[NormalizedEvent | ParseFailure]:
        """Stream the file's records into events and failures."""
        backend = self._backend
        if backend is None:
            backend = "native" if _native_available() else "vendored"
        if backend == "native":
            yield from self._parse_native(context)
        else:
            yield from self._parse_vendored(context)

    def _parse_native(self, context: ParseContext) -> Iterator[NormalizedEvent | ParseFailure]:
        """Read through pyevtx-rs, which yields one JSON record at a time."""
        parser = _native_parser(context)
        count = 0
        try:
            for item in parser.records_json():
                count += 1
                record_ref = f"record:{count}"
                if isinstance(item, BaseException):
                    context.counters.record_failure()
                    yield ParseFailure(record_ref, f"invalid record: {item}", None)
                    continue
                event = self._native_record(context, item, record_ref)
                if isinstance(event, ParseFailure):
                    context.counters.record_failure()
                else:
                    context.counters.record_event(event)
                yield event
        except RuntimeError as error:
            # The native reader stops at a record it cannot decode. Report where
            # it stopped and keep that as the end of this file's records.
            context.counters.record_failure()
            yield ParseFailure(
                record_ref=f"record:{count + 1}",
                reason=f"reader stopped at a corrupt record: {error}",
                raw_excerpt=None,
            )

    def _native_record(
        self,
        context: ParseContext,
        item: Any,
        record_ref: str,
    ) -> NormalizedEvent | ParseFailure:
        """Map one JSON string from the native reader."""
        import json

        try:
            event_dict = json.loads(item) if isinstance(item, str) else item
        except json.JSONDecodeError as error:
            return ParseFailure(record_ref, f"invalid JSON from reader: {error}", None)
        if not isinstance(event_dict, dict):
            return ParseFailure(record_ref, "reader returned a non-object record", None)
        raw = item if isinstance(item, str) else json.dumps(item, ensure_ascii=False)
        try:
            return map_event_dict(
                event_dict,
                context=context,
                log_type=self.log_type,
                raw=raw,
                record_ref=record_ref,
            )
        except (KeyError, TypeError, ValueError) as error:
            return ParseFailure(record_ref, f"could not map event: {error}", raw[:200])

    def _parse_vendored(self, context: ParseContext) -> Iterator[NormalizedEvent | ParseFailure]:
        """Read through the vendored reader, one chunk at a time."""
        reader = _vendored_reader(context)
        count = 0
        with reader as evtx_file:
            for chunk_index, chunk in enumerate(evtx_file.chunks()):
                try:
                    for record in chunk.records():
                        count += 1
                        record_ref = f"record:{count}"
                        event = self._vendored_record(context, record, record_ref)
                        if isinstance(event, ParseFailure):
                            context.counters.record_failure()
                        else:
                            context.counters.record_event(event)
                        yield event
                except _vendored_error() as error:
                    # One bad chunk: report it, then continue with the next.
                    context.counters.record_failure()
                    yield ParseFailure(
                        record_ref=f"chunk:{chunk_index}",
                        reason=f"chunk could not be decoded: {error}",
                        raw_excerpt=None,
                    )

    def _vendored_record(
        self,
        context: ParseContext,
        record: Any,
        record_ref: str,
    ) -> NormalizedEvent | ParseFailure:
        """Map one record from the vendored reader through its element form."""
        try:
            element = record.lxml()
            event_dict = event_dict_from_element(element)
            raw = record.xml()
        except Exception as error:  # the vendored reader raises its own hierarchy
            return ParseFailure(record_ref, f"could not read record: {error}", None)
        try:
            return map_event_dict(
                event_dict,
                context=context,
                log_type=self.log_type,
                raw=raw,
                record_ref=record_ref,
            )
        except (KeyError, TypeError, ValueError) as error:
            return ParseFailure(record_ref, f"could not map event: {error}", raw[:200])


def _native_available() -> bool:
    """Whether the native extension imported successfully."""
    return _PyEvtxParser is not None


def _native_parser(context: ParseContext) -> Any:
    """A pyevtx-rs parser for the file in ``context``."""
    return _PyEvtxParser(str(context.path))


def _vendored_reader(context: ParseContext) -> Any:
    """A vendored ``Evtx`` reader for the file in ``context``."""
    from app.ingest.parsers.evtxlib.Evtx import Evtx

    return Evtx(str(context.path))  # type: ignore[no-untyped-call]


def _vendored_error() -> type[BaseException]:
    """The vendored reader's own exception type, for the chunk guard."""
    from app.ingest.parsers import evtxlib

    return evtxlib.Evtx.ParseException


def build() -> WindowsEvtxParser:
    """Construct the parser for the registry."""
    return WindowsEvtxParser()


_register(build())


__all__ = ["EVTX_MAGIC", "WindowsEvtxParser", "build"]
