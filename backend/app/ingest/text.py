"""Streaming text reader shared by every text parser (spec 03 section 1).

The reading rules live in one place because they must be identical for every
format: a file parsed by two different code paths has to produce the same
records either way.

The guarantees:

- **Bounded memory.** Lines arrive one at a time from a decompressing stream, so
  a 50 GB gzip costs one line of RAM.
- **Never lossy by accident.** Invalid UTF-8 becomes U+FFFD rather than raising,
  a BOM is stripped rather than becoming part of the first record, and CRLF is
  normalized. The tail of an oversized line is replaced by an explicit marker and
  reported, never silently dropped.
"""

from __future__ import annotations

import codecs
import gzip
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, cast

from app.ingest.normalize import truncate

#: Bytes read from a file when sniffing content (spec 03 section 1).
SNIFF_BYTES = 64 * 1024

#: Lines read from a text file when sniffing.
SNIFF_LINES = 200

#: Read size for the line assembler. Large enough to amortize syscalls on a
#: multi-gigabyte file, small enough to stay well inside the worker memory cap.
CHUNK_BYTES = 1 << 20

#: Shortest sample worth testing the UTF-16 NUL-byte heuristic against.
_UTF16_MIN_SAMPLE = 4

#: Fallback when no BOM is present. UTF-8 is assumed because it is a superset of
#: ASCII and the overwhelmingly common case; errors are replaced so one stray
#: byte cannot fail an entire file.
DEFAULT_ENCODING = "utf-8"

#: Byte-order marks, longest first so UTF-32 is not misread as UTF-16.
_BOMS: tuple[tuple[bytes, str], ...] = (
    (b"\xff\xfe\x00\x00", "utf-32-le"),
    (b"\x00\x00\xfe\xff", "utf-32-be"),
    (b"\xff\xfe", "utf-16-le"),
    (b"\xfe\xff", "utf-16-be"),
    (b"\xef\xbb\xbf", "utf-8-sig"),
)

#: Longest BOM, and how much is read to detect one.
_MAX_BOM = 4


def decode_bytes(data: bytes) -> str:
    """Decode a byte string, honouring a BOM and replacing invalid sequences.

    UTF-16 without a BOM is undetectable from bytes alone, so it is not guessed
    here; :func:`looks_utf16` lets a caller ask first.
    """
    encoding, remainder = split_bom(data)
    return remainder.decode(encoding or DEFAULT_ENCODING, errors="replace")


def split_bom(data: bytes) -> tuple[str | None, bytes]:
    """Split a leading byte-order mark off ``data``.

    Returns the encoding it implies and the bytes after it. ``None`` means there
    was no mark and the data should be decoded as-is.
    """
    for bom, encoding in _BOMS:
        if data.startswith(bom):
            remainder = data[len(bom) :]
            return ("utf-8" if encoding == "utf-8-sig" else encoding), remainder
    return None, data


def looks_utf16(data: bytes) -> bool:
    """Heuristic: does this look like BOM-less UTF-16?

    Real UTF-16 text is dominated by NUL bytes in one byte position, because
    ASCII characters occupy one byte and zero the other. A false positive costs
    only a garbled read of a file that was not UTF-16 to begin with, and every
    other byte-oriented guess would be worse.
    """
    sample = data[:4096]
    if len(sample) < _UTF16_MIN_SAMPLE:
        return False
    half = len(sample) // 2
    return sample[0::2].count(0) > half * 0.3 or sample[1::2].count(0) > half * 0.3


def open_binary(path: Path) -> BinaryIO:
    """Open ``path`` for binary reading, transparently decompressing ``.gz``.

    A ``.gz`` that is not actually gzip is returned undecoded rather than
    raising: intake stores what was uploaded, and detection decides what it is.
    """
    if path.suffix.lower() == ".gz":
        try:
            # The stream is returned to the caller, so it must not be closed here.
            # GzipFile is binary-readable but is not declared as IO[bytes].
            stream = cast("BinaryIO", gzip.open(path, "rb"))  # noqa: SIM115
            stream.read(1)
            stream.seek(0)
        except (OSError, EOFError):
            return path.open("rb")
        else:
            return stream
    return path.open("rb")


@dataclass(slots=True)
class TextHead:
    """A bounded prefix of a file, for detection.

    Detection must not read a whole file to decide what it is, so this holds only
    enough bytes for a magic-number check and enough lines for a sampling vote.
    """

    head: bytes
    lines: list[str] = field(default_factory=list)
    #: The uploaded filename, so a parser can use a name hint (``auth.log``,
    #: ``secure``) during detection. Optional because a head can be built for a
    #: byte blob with no name at all.
    name: str | None = None

    @property
    def text(self) -> str:
        """The prefix decoded, for regex sniffing."""
        return decode_bytes(self.head)


def read_head(
    path: Path,
    *,
    max_bytes: int = SNIFF_BYTES,
    max_lines: int = SNIFF_LINES,
    name: str | None = None,
) -> TextHead:
    """Read a bounded prefix of ``path`` for sniffing."""
    with open_binary(path) as handle:
        head = handle.read(max_bytes)
    lines = decode_bytes(head).split("\n")[:max_lines]
    return TextHead(head=head, lines=[line.rstrip("\r") for line in lines], name=name)


def iter_text_lines(
    path: Path, *, max_line_bytes: int, encoding: str | None = None
) -> Iterator[tuple[int, str, bool]]:
    """Yield ``(line_number, text, was_truncated)`` for each line of ``path``.

    Line numbers are 1-based, matching the ``line:<n>`` record references the
    schema uses. Blank lines are yielded rather than skipped: deciding what
    counts as a record is the parser's job, and filtering them here would make
    the record count disagree with the line count.
    """
    with open_binary(path) as handle:
        for line_number, line in enumerate(_decoded_lines(handle, encoding), start=1):
            text, was_truncated = truncate(line.rstrip("\r"), max_line_bytes)
            yield line_number, text, was_truncated


def _decoded_lines(handle: BinaryIO, encoding: str | None) -> Iterator[str]:
    """Decode a binary stream into lines without ever holding the whole file.

    The BOM is consumed from the first chunk rather than by seeking, because
    neither :class:`gzip.GzipFile` nor a plain file object supports pushback.
    """
    chosen = encoding
    first = handle.read(CHUNK_BYTES)
    if chosen is None:
        bom_encoding, remainder = split_bom(first)
        if bom_encoding is not None:
            # The mark is already gone, so plain UTF-8 avoids a second strip.
            chosen = "utf-8" if bom_encoding == "utf-8-sig" else bom_encoding
        elif looks_utf16(remainder):
            chosen = "utf-16-le"
        else:
            chosen = DEFAULT_ENCODING
        first = remainder

    # The stdlib decoder is what keeps a multi-byte character from being split
    # across a chunk boundary, which would otherwise corrupt a record.
    decoder = codecs.getincrementaldecoder(chosen)(errors="replace")
    buffer = ""
    for chunk in _byte_chunks(first, handle):
        buffer += decoder.decode(chunk)
        start = 0
        while (index := buffer.find("\n", start)) != -1:
            yield buffer[start:index]
            start = index + 1
        buffer = buffer[start:]
    buffer += decoder.decode(b"", final=True)
    if buffer:
        yield buffer


def _byte_chunks(first: bytes, handle: BinaryIO) -> Iterator[bytes]:
    """Yield byte chunks, starting with the already-read first one."""
    if first:
        yield first
    while True:
        chunk = handle.read(CHUNK_BYTES)
        if not chunk:
            return
        yield chunk


def sniff_name(filename: str) -> str:
    """Lowercased basename, used for the filename hints in detection."""
    return Path(filename).name.lower()


__all__ = [
    "CHUNK_BYTES",
    "DEFAULT_ENCODING",
    "SNIFF_BYTES",
    "SNIFF_LINES",
    "TextHead",
    "decode_bytes",
    "iter_text_lines",
    "looks_utf16",
    "open_binary",
    "read_head",
    "sniff_name",
    "split_bom",
]
