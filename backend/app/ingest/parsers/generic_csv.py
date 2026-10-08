"""Generic CSV parser driven by a mapping profile (spec 03 section 6).

A CSV file is header-labelled rows, so once the header and delimiter are known a
row is just a mapping of column name to cell. That makes it the same shape the
JSON parser already maps, which is why the profile engine is shared: only the
record readers differ.

Two shapes are handled in one pass:

- a plain table, whose first non-comment line is the header and whose delimiter
  is sniffed among comma, semicolon, tab and pipe;
- a Zeek TSV, whose ``#separator`` and ``#fields`` directives name the delimiter
  and the columns, with the remaining ``#`` lines skipped as comments.
"""

from __future__ import annotations

import csv
from collections.abc import Iterator

from app.ingest.events import NormalizedEvent
from app.ingest.parsers.base import ParseContext, ParseFailure, _register
from app.ingest.parsers.generic_common import (
    load_profiles_cached,
    map_record,
    pick_profile,
)
from app.ingest.profiles import Profile, ProfileError
from app.ingest.text import TextHead, iter_text_lines

#: Delimiters tried, in priority order, when nothing names one explicitly.
_CANDIDATE_DELIMITERS: tuple[str, ...] = (",", ";", "\t", "|")

#: How many non-empty lines inform the delimiter guess.
_SNIFF_SAMPLE = 20

#: Fewer columns than this is not a table.
_MIN_COLUMNS = 2

#: A directive line is ``#fields ts uid ...``; the value is everything after it.
_DIRECTIVE_SEPARATOR = "separator"
_DIRECTIVE_FIELDS = "fields"

#: Zeek escapes its separator; accept both the literal ``\x09`` form and ``\t``.
_SEPARATOR_ESCAPES: dict[str, str] = {
    "\\x09": "\t",
    "\\t": "\t",
    "\\x20": " ",
    "\\x2c": ",",
    "\\x3b": ";",
    "\\x7c": "|",
}


def _split(line: str, delimiter: str) -> list[str]:
    """Split one line, honouring quoted fields the way a spreadsheet does."""
    try:
        return next(csv.reader([line], delimiter=delimiter))
    except (csv.Error, StopIteration):
        return line.split(delimiter)


def _decode_separator(value: str) -> str:
    """Turn a Zeek separator token into the character it names."""
    token = value.strip()
    if token in _SEPARATOR_ESCAPES:
        return _SEPARATOR_ESCAPES[token]
    return token[:1] or "\t"


def _directive(line: str) -> tuple[str, str] | None:
    """Split ``#fields ...`` into ``("fields", "...")``; ``None`` for other lines.

    Only the two directives that carry table structure are reported; ``#types``,
    ``#path`` and friends are ignored by the caller.
    """
    stripped = line.lstrip()
    if not stripped.startswith("#"):
        return None
    body = stripped[1:]
    parts = body.split(None, 1)
    if not parts:
        return None
    lowered = parts[0].strip().lower()
    value = parts[1] if len(parts) > 1 else ""
    if lowered == _DIRECTIVE_SEPARATOR:
        return (_DIRECTIVE_SEPARATOR, value)
    if lowered == _DIRECTIVE_FIELDS:
        return (_DIRECTIVE_FIELDS, value)
    return None


def _sniff_delimiter(lines: list[str]) -> str | None:
    """The delimiter producing the most consistent column count, or ``None``.

    Consistency matters more than raw width: a comma-separated line is also
    "consistent" under a pipe delimiter (every row is one column), so the winner
    must both split into at least two columns and agree with itself across rows.
    """
    best: str | None = None
    best_score = 0.0
    for delimiter in _CANDIDATE_DELIMITERS:
        counts = [len(_split(line, delimiter)) for line in lines if line.strip()]
        if not counts or counts[0] < _MIN_COLUMNS:
            continue
        common = max(set(counts), key=counts.count)
        if common < _MIN_COLUMNS:
            continue
        score = counts.count(common) / len(counts)
        if score > best_score:
            best_score = score
            best = delimiter
    return best


def scan_header(lines: list[str]) -> tuple[list[str], str] | None:
    """Find the header row and delimiter in a sample of lines, or ``None``.

    Shared with :meth:`GenericCsvParser.sniff`; the streaming parser inlines the
    same rules so it need not hold the whole file.
    """
    delimiter: str | None = None
    for line in lines:
        if not line.strip():
            continue
        directive = _directive(line)
        if directive is not None:
            kind, value = directive
            if kind == _DIRECTIVE_SEPARATOR:
                delimiter = _decode_separator(value)
            else:
                delimiter = delimiter or "\t"
                header = _split(value, delimiter)
                return (header, delimiter) if len(header) >= _MIN_COLUMNS else None
            continue
        if line.lstrip().startswith("#"):
            continue
        guessed = _sniff_delimiter(lines) or ","
        header = _split(line, guessed)
        return (header, guessed) if len(header) >= _MIN_COLUMNS else None
    return None


class GenericCsvParser:
    """Delimited records, mapped through a profile."""

    __slots__ = ("_profiles",)

    log_type = "generic_csv"

    def __init__(self, profiles: dict[str, Profile] | None = None) -> None:
        self._profiles = profiles

    def sniff(self, head: TextHead) -> float:
        """0.9 for a Zeek TSV, 0.85 for a table a profile claims, else a weak table.

        A CSV of unknown columns is only worth 0.5: the format is ``generic_csv``
        either way, but claiming it confidently for a file no profile can map
        would hide the "choose a mapping profile" prompt behind a decision the
        parser cannot honour.
        """
        lines = [line for line in head.lines if line.strip()]
        scanned = scan_header(lines)
        if scanned is None:
            return 0.0
        header, _delimiter = scanned
        if any(_is_fields_directive(line) for line in lines):
            return 0.9
        profiles = self._profiles if self._profiles is not None else load_profiles_cached()
        columns = set(header)
        for profile in profiles.values():
            if profile.applies_when_keys & columns:
                return 0.85
        return 0.5

    def parse(self, context: ParseContext) -> Iterator[NormalizedEvent | ParseFailure]:
        """Stream the file into events and failures, one per data row."""
        for item in self._records(context):
            if isinstance(item, ParseFailure):
                context.counters.record_failure()
            else:
                context.counters.record_event(item)
            yield item

    def _records(self, context: ParseContext) -> Iterator[NormalizedEvent | ParseFailure]:
        profiles = self._profiles if self._profiles is not None else load_profiles_cached()
        lines = iter_text_lines(context.path, max_line_bytes=context.max_line_bytes)
        header: list[str] | None = None
        delimiter = "\t"
        for line_number, text, truncated in lines:
            if not text.strip():
                continue
            if text.lstrip().startswith("#"):
                # Zeek's ``#close`` and friends are comments wherever they sit,
                # so a directive-looking line after the header is skipped too.
                if header is None:
                    directive = _directive(text)
                    if directive is not None:
                        kind, value = directive
                        if kind == _DIRECTIVE_SEPARATOR:
                            delimiter = _decode_separator(value)
                        else:
                            header = _split(value, delimiter)
                            if len(header) < _MIN_COLUMNS:
                                yield ParseFailure(
                                    f"line:{line_number}",
                                    "the #fields directive names fewer than two columns",
                                    text,
                                )
                                return
                continue
            if header is None:
                sample, buffered = _sample(lines, text)
                guessed = _sniff_delimiter(sample) or ","
                delimiter = guessed
                header = _split(text, guessed)
                if len(header) < _MIN_COLUMNS:
                    yield ParseFailure(
                        f"line:{line_number}",
                        "the header row names fewer than two columns",
                        text,
                    )
                    return
                for buffered_number, buffered_text, buffered_truncated in buffered:
                    yield from self._row(
                        context,
                        profiles,
                        header=header,
                        delimiter=delimiter,
                        line_number=buffered_number,
                        text=buffered_text,
                        truncated=buffered_truncated,
                    )
                continue
            yield from self._row(
                context,
                profiles,
                header=header,
                delimiter=delimiter,
                line_number=line_number,
                text=text,
                truncated=truncated,
            )

    def _row(
        self,
        context: ParseContext,
        profiles: dict[str, Profile],
        *,
        header: list[str],
        delimiter: str,
        line_number: int,
        text: str,
        truncated: bool,
    ) -> Iterator[NormalizedEvent | ParseFailure]:
        """Turn one data line into an event or a failure."""
        if text.lstrip().startswith("#"):
            return
        record_ref = f"line:{line_number}"
        if truncated:
            yield ParseFailure(record_ref, "line exceeded max_line_bytes", text)
            return
        fields = _split(text, delimiter)
        if len(fields) != len(header):
            yield ParseFailure(
                record_ref,
                f"expected {len(header)} columns, found {len(fields)}",
                text,
            )
            return
        record = dict(zip(header, fields, strict=True))
        profile = pick_profile(record, profiles)
        if profile is None:
            yield ParseFailure(record_ref, "no mapping profile matches this record", text)
            return
        yield map_record(
            context=context,
            profile=profile,
            record=record,
            record_ref=record_ref,
            raw=text,
            log_type=self.log_type,
        )


def _is_fields_directive(line: str) -> bool:
    """True for a Zeek ``#fields`` line."""
    directive = _directive(line)
    return directive is not None and directive[0] == _DIRECTIVE_FIELDS


def _sample(
    lines: Iterator[tuple[int, str, bool]], first: str
) -> tuple[list[str], list[tuple[int, str, bool]]]:
    """Pull a small lookahead so the delimiter can be guessed from several rows.

    Returns the non-empty sample texts and the buffered ``(line, text, truncated)``
    tuples, so the caller can process those rows once the header is known without
    re-reading the file.
    """
    sample = [first]
    buffered: list[tuple[int, str, bool]] = []
    for item in lines:
        buffered.append(item)
        if item[1].strip():
            sample.append(item[1])
        if len(buffered) >= _SNIFF_SAMPLE:
            break
    return sample, buffered


def build() -> GenericCsvParser:
    """Construct the parser for the registry."""
    try:
        return GenericCsvParser(load_profiles_cached())
    except ProfileError:
        return GenericCsvParser({})


_register(build())


__all__ = ["GenericCsvParser", "build", "scan_header"]
