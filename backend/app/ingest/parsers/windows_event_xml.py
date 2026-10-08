"""Windows Event Log XML parser (spec 03 section 2).

This is the text counterpart of :mod:`app.ingest.parsers.windows_evtx`: the same
``<Event>`` records, exported by ``wevtutil`` or produced by tooling, mapped
through the one shared table in :mod:`app.ingest.parsers.windows_common`. The two
parsers must agree on every column, so the mapping lives in neither of them.

Two hard requirements shape the reading:

- **Bounded memory.** A multi-gigabyte export must not be loaded whole, so the
  file is pushed through :class:`lxml.etree.XMLPullParser` in chunks and each
  ``<Event>`` is released as soon as it is mapped.
- **No entity expansion (spec 09 S-08).** The parser runs with
  ``resolve_entities=False``, ``no_network=True``, ``load_dtd=False`` and
  ``huge_tree=False``, so an XML bomb or an XXE payload in a hostile log cannot
  read local files or exhaust memory.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from lxml import etree

from app.ingest.events import NormalizedEvent
from app.ingest.parsers.base import (
    ParseContext,
    ParseFailure,
    _register,
)
from app.ingest.parsers.windows_common import event_dict_from_element, map_event_dict
from app.ingest.text import TextHead, open_binary

#: The namespace every Windows event ``<Event>`` carries when exported.
EVENT_NAMESPACE = "http://schemas.microsoft.com/win/2004/08/events/event"

#: A cheap check for an ``Event``/``Events`` element before doing any parsing.
_EVENT_MARKER = re.compile(r"<\s*(events?)\b", re.IGNORECASE)

#: Read size for the pull parser. Large enough to amortize syscalls, small enough
#: that memory stays flat on a huge file.
_READ_CHUNK = 1 << 20


class WindowsEventXmlParser:
    """``<Event>`` documents, streamed through a hardened pull parser."""

    __slots__ = ()

    log_type = "windows_event_xml"

    def sniff(self, head: TextHead) -> float:
        """Score how much the head looks like Windows event XML.

        A Windows events export is claimed strongly; a generic ``<Event>``
        without the schema namespace is a weaker guess. Anything else is 0.0, so
        an unrelated XML file is not quietly parsed into zero events.
        """
        text = head.text.lstrip("\ufeff \t\r\n")
        if not text:
            return 0.0
        if EVENT_NAMESPACE in text:
            return 0.95
        lowered = text.lower()
        if "<events" in lowered:
            return 0.95
        if _EVENT_MARKER.search(text):
            return 0.7
        return 0.0

    def parse(self, context: ParseContext) -> Iterator[NormalizedEvent | ParseFailure]:
        """Stream every ``<Event>`` in the file into an event or a failure."""
        parser = etree.XMLPullParser(
            events=("end",),
            resolve_entities=False,
            no_network=True,
            load_dtd=False,
            huge_tree=False,
            recover=False,
        )
        state = {"index": 0}
        try:
            with open_binary(context.path) as handle:
                while True:
                    chunk = handle.read(_READ_CHUNK)
                    if not chunk:
                        break
                    parser.feed(chunk)
                    yield from self._drain(parser, context, state)
                parser.close()
                yield from self._drain(parser, context, state)
        except etree.XMLSyntaxError as error:
            context.counters.record_failure()
            yield ParseFailure(
                record_ref=f"record:{state['index'] + 1}",
                reason=f"XML is not well formed: {error}",
                raw_excerpt=None,
            )

    def _drain(
        self,
        parser: etree.XMLPullParser,
        context: ParseContext,
        state: dict[str, int],
    ) -> Iterator[NormalizedEvent | ParseFailure]:
        """Map each completed ``<Event>`` and release it from the tree."""
        for _event, element in parser.read_events():
            tag = element.tag
            if not isinstance(tag, str):
                continue
            if etree.QName(tag).localname != "Event":
                continue
            state["index"] += 1
            item = self._to_event(context, element, state["index"])
            if isinstance(item, ParseFailure):
                context.counters.record_failure()
            else:
                context.counters.record_event(item)
            yield item
            element.clear()
            _drop_previous(element)

    def _to_event(
        self,
        context: ParseContext,
        element: Any,
        index: int,
    ) -> NormalizedEvent | ParseFailure:
        """Map one ``<Event>`` element, reporting rather than raising on failure."""
        record_ref = f"record:{index}"
        try:
            event_dict = event_dict_from_element(element)
            raw = etree.tostring(element, encoding="unicode")
        except (etree.LxmlError, ValueError) as error:
            return ParseFailure(record_ref, f"could not read event: {error}", None)
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


def _drop_previous(element: Any) -> None:
    """Remove already-processed siblings to keep memory flat on large exports."""
    parent = element.getparent()
    if parent is None:
        return
    while element.getprevious() is not None:
        del parent[0]


def build() -> WindowsEventXmlParser:
    """Construct the parser for the registry."""
    return WindowsEventXmlParser()


_register(build())


__all__ = ["EVENT_NAMESPACE", "WindowsEventXmlParser", "build"]
