"""Text reading rules (spec 03 section 1; spec 09 P-03, P-04).

These cover the inputs that historically break log parsers: byte-order marks,
UTF-16 without a BOM, CRLF, gzip, invalid UTF-8 and a single enormous line.
"""

from __future__ import annotations

import gzip
from pathlib import Path

import pytest

from app.ingest.normalize import TRUNCATION_MARKER
from app.ingest.text import (
    decode_bytes,
    iter_text_lines,
    looks_utf16,
    open_binary,
    read_head,
    split_bom,
)


def write(tmp_path: Path, name: str, data: bytes) -> Path:
    """Write raw bytes and return the path."""
    path = tmp_path / name
    path.write_bytes(data)
    return path


class TestBomHandling:
    """P-03: a BOM must be stripped, not stored as part of the first record."""

    def test_utf8_bom_is_stripped(self, tmp_path: Path) -> None:
        path = write(tmp_path, "bom.log", b"\xef\xbb\xbffirst\nsecond\n")
        lines = [text for _, text, _ in iter_text_lines(path, max_line_bytes=1000)]
        assert lines == ["first", "second"]

    @pytest.mark.parametrize(
        ("encoding", "bom"),
        [
            ("utf-16-le", b"\xff\xfe"),
            ("utf-16-be", b"\xfe\xff"),
        ],
    )
    def test_utf16_bom_is_detected_and_decoded(
        self, tmp_path: Path, encoding: str, bom: bytes
    ) -> None:
        path = write(tmp_path, "u16.log", bom + "alpha\nbeta\n".encode(encoding))
        lines = [text for _, text, _ in iter_text_lines(path, max_line_bytes=1000)]
        assert lines == ["alpha", "beta"]

    def test_utf16_without_bom_is_detected(self, tmp_path: Path) -> None:
        path = write(tmp_path, "nobom.log", "alpha\nbeta\n".encode("utf-16-le"))
        lines = [text for _, text, _ in iter_text_lines(path, max_line_bytes=1000)]
        assert lines == ["alpha", "beta"]

    def test_split_bom_reports_encoding_and_remainder(self) -> None:
        encoding, remainder = split_bom(b"\xef\xbb\xbfrest")
        assert (encoding, remainder) == ("utf-8", b"rest")

    def test_split_bom_without_mark_is_passthrough(self) -> None:
        assert split_bom(b"plain") == (None, b"plain")

    def test_decode_bytes_replaces_invalid_sequences(self) -> None:
        assert decode_bytes(b"ok\xffbad") == "ok\ufffdbad"

    def test_looks_utf16_only_for_utf16(self) -> None:
        assert looks_utf16("alpha\nbeta\n".encode("utf-16-le")) is True
        assert looks_utf16(b"alpha\nbeta\n") is False

    def test_utf32_bom_is_not_mistaken_for_utf16(self) -> None:
        encoding, _ = split_bom(b"\xff\xfe\x00\x00rest")
        assert encoding == "utf-32-le"


class TestLineFraming:
    """CRLF, blank lines and line numbering."""

    def test_crlf_is_normalized(self, tmp_path: Path) -> None:
        path = write(tmp_path, "crlf.log", b"one\r\ntwo\r\n")
        lines = [text for _, text, _ in iter_text_lines(path, max_line_bytes=1000)]
        assert lines == ["one", "two"]

    def test_blank_lines_are_yielded_not_skipped(self, tmp_path: Path) -> None:
        path = write(tmp_path, "blank.log", b"one\n\ntwo\n")
        lines = [text for _, text, _ in iter_text_lines(path, max_line_bytes=1000)]
        assert lines == ["one", "", "two"]

    def test_line_numbers_are_one_based(self, tmp_path: Path) -> None:
        path = write(tmp_path, "num.log", b"a\nb\nc\n")
        numbers = [number for number, _, _ in iter_text_lines(path, max_line_bytes=1000)]
        assert numbers == [1, 2, 3]

    def test_final_line_without_newline_is_yielded(self, tmp_path: Path) -> None:
        path = write(tmp_path, "noeol.log", b"a\nb")
        lines = [text for _, text, _ in iter_text_lines(path, max_line_bytes=1000)]
        assert lines == ["a", "b"]

    def test_empty_file_yields_nothing(self, tmp_path: Path) -> None:
        path = write(tmp_path, "empty.log", b"")
        assert list(iter_text_lines(path, max_line_bytes=1000)) == []


class TestGzip:
    """P-03: gzip members are transparently streamed."""

    def test_gzip_is_decompressed(self, tmp_path: Path) -> None:
        path = tmp_path / "access.log.gz"
        with gzip.open(path, "wb") as handle:
            handle.write(b"one\ntwo\n")
        lines = [text for _, text, _ in iter_text_lines(path, max_line_bytes=1000)]
        assert lines == ["one", "two"]

    def test_fake_gz_extension_is_read_raw(self, tmp_path: Path) -> None:
        path = write(tmp_path, "not-really.log.gz", b"plain text\n")
        lines = [text for _, text, _ in iter_text_lines(path, max_line_bytes=1000)]
        assert lines == ["plain text"]

    def test_open_binary_returns_a_usable_stream(self, tmp_path: Path) -> None:
        path = write(tmp_path, "plain.log", b"data\n")
        with open_binary(path) as handle:
            assert handle.read() == b"data\n"


class TestTruncation:
    """P-04: an oversized line is truncated with a marker and flagged."""

    def test_long_line_is_truncated_and_flagged(self, tmp_path: Path) -> None:
        path = write(tmp_path, "long.log", b"x" * 5000 + b"\nshort\n")
        results = list(iter_text_lines(path, max_line_bytes=100))
        _number, first_text, first_flag = results[0]
        assert first_flag is True
        assert first_text.endswith(TRUNCATION_MARKER)
        assert len(first_text.encode("utf-8")) <= 100
        assert results[1][2] is False

    def test_truncation_lands_on_a_character_boundary(self, tmp_path: Path) -> None:
        # Each emoji is 4 bytes, so a naive byte slice would split one.
        path = write(tmp_path, "emoji.log", ("\U0001f600" * 100).encode("utf-8") + b"\n")
        _, text, flagged = next(iter(iter_text_lines(path, max_line_bytes=50)))
        assert flagged is True
        assert text.endswith(TRUNCATION_MARKER)
        assert "\ufffd" not in text

    def test_marker_appears_exactly_once(self, tmp_path: Path) -> None:
        path = write(tmp_path, "once.log", b"y" * 300 + b"\n")
        _, text, _ = next(iter(iter_text_lines(path, max_line_bytes=100)))
        assert text.count(TRUNCATION_MARKER) == 1


class TestChunkBoundary:
    """A multi-byte character split across a read boundary must survive."""

    def test_multibyte_character_across_chunks_is_intact(self, tmp_path: Path) -> None:
        from app.ingest.text import CHUNK_BYTES

        # Place a 4-byte character so it straddles the first chunk boundary.
        filler = b"a" * (CHUNK_BYTES - 2)
        path = write(tmp_path, "boundary.log", filler + "\U0001f600\n".encode("utf-8"))
        lines = [text for _, text, _ in iter_text_lines(path, max_line_bytes=10_000_000)]
        assert lines == [filler.decode() + "\U0001f600"]


class TestReadHead:
    """Detection reads a bounded prefix."""

    def test_head_caps_bytes_and_lines(self, tmp_path: Path) -> None:
        path = write(tmp_path, "big.log", b"".join(b"line %d\n" % n for n in range(1000)))
        head = read_head(path, max_bytes=1024, max_lines=5)
        assert len(head.head) <= 1024
        assert len(head.lines) <= 5

    def test_head_strips_carriage_returns(self, tmp_path: Path) -> None:
        path = write(tmp_path, "crlf.log", b"one\r\ntwo\r\n")
        assert read_head(path).lines[:2] == ["one", "two"]

    def test_head_text_is_decoded(self, tmp_path: Path) -> None:
        path = write(tmp_path, "t.log", b"hello\n")
        assert "hello" in read_head(path).text
