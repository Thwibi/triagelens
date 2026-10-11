"""Disk-space guard (spec 10 section 1, "Disk exhaustion").

The guard is exercised by faking ``shutil.disk_usage`` rather than by filling a
real filesystem: the two rules - free space at least three times the incoming
bytes, and a free fraction above the configured floor - are pure arithmetic on
the usage figures, so a fake makes every branch reachable deterministically.
"""

from __future__ import annotations

import shutil
from collections import namedtuple
from pathlib import Path

import pytest

from app.errors import ApiError, ErrorCode
from app.ingest.archive import (
    FILESYSTEM_HEADROOM_FACTOR,
    ensure_disk_space,
)

_Usage = namedtuple("_Usage", ["total", "used", "free"])


def _fake_usage(monkeypatch: pytest.MonkeyPatch, *, total: int, free: int) -> None:
    def fake(path: object) -> _Usage:
        return _Usage(total=total, used=total - free, free=free)

    monkeypatch.setattr(shutil, "disk_usage", fake)


def test_headroom_factor_is_three() -> None:
    """The spec's ">= 3x file size" is captured as one named constant."""
    assert FILESYSTEM_HEADROOM_FACTOR == 3


def test_enough_space_passes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _fake_usage(monkeypatch, total=1_000_000, free=500_000)
    ensure_disk_space(tmp_path, needed_bytes=1000, min_free_fraction=0.05)


def test_three_times_headroom_is_required(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Free space below three times the incoming size is refused."""
    _fake_usage(monkeypatch, total=1_000_000, free=100)
    with pytest.raises(ApiError) as caught:
        ensure_disk_space(tmp_path, needed_bytes=40, min_free_fraction=0.0)
    assert caught.value.code is ErrorCode.INSUFFICIENT_STORAGE
    assert caught.value.status_code == 507
    assert caught.value.details["required_bytes"] == 120
    assert caught.value.details["free_bytes"] == 100


def test_exactly_three_times_is_accepted(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _fake_usage(monkeypatch, total=1_000_000, free=120)
    ensure_disk_space(tmp_path, needed_bytes=40, min_free_fraction=0.0)


def test_free_fraction_floor_is_enforced(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A free fraction under the floor is refused even when the size fits."""
    _fake_usage(monkeypatch, total=1000, free=40)
    with pytest.raises(ApiError) as caught:
        ensure_disk_space(tmp_path, needed_bytes=0, min_free_fraction=0.05)
    assert caught.value.code is ErrorCode.INSUFFICIENT_STORAGE
    assert caught.value.details["required_bytes"] == 50


def test_zero_needed_bytes_only_applies_the_floor(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """With no size estimate the headroom rule is skipped, the floor still holds."""
    _fake_usage(monkeypatch, total=1_000_000, free=100_000)
    ensure_disk_space(tmp_path, needed_bytes=0, min_free_fraction=0.05)
