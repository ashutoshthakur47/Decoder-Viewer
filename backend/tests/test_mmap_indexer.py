"""Tests for the mmap sparse log indexer."""
from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path

import pytest

from app.log_indexer import MmapLogIndexer
from app.schemas import TokenState


@pytest.fixture()
def fifty_thousand_lines():
    handle = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", suffix=".log", delete=False, newline="\n"
    )
    path = handle.name
    try:
        for index in range(50_000):
            handle.write(f"line-{index:06d} value={index}\n")
        handle.close()
        yield path
    finally:
        try:
            handle.close()
        except Exception:
            pass
        if os.path.exists(path):
            os.unlink(path)


def test_total_line_count(fifty_thousand_lines: str):
    with MmapLogIndexer(fifty_thousand_lines) as indexer:
        assert indexer.total_lines == 50_000
        assert indexer.file_size_bytes > 0
        assert indexer.sparse_offsets[0] == 0
        # A sample offset is stored for line indices 0, 1000, ..., 49000.
        assert len(indexer.sparse_offsets) == 50


def test_random_access_is_exact_and_fast(fifty_thousand_lines: str):
    with MmapLogIndexer(fifty_thousand_lines) as indexer:
        # Warm the mmap page cache, then take the best of three jumps.
        indexer.get_lines(42_500, 10)
        timings = []
        for _ in range(3):
            started = time.perf_counter()
            lines = indexer.get_lines(42_500, 10)
            timings.append(time.perf_counter() - started)

        assert [number for number, _ in lines] == list(range(42_501, 42_511))
        assert [text for _, text in lines] == [
            f"line-{index:06d} value={index}" for index in range(42_500, 42_510)
        ]
        assert min(timings) < 0.02, f"random access too slow: {min(timings):.5f}s"


def test_line_without_trailing_newline():
    handle = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", suffix=".log", delete=False, newline="\n"
    )
    path = handle.name
    handle.write("first\nsecond\nthird-without-newline")
    handle.close()
    try:
        with MmapLogIndexer(path) as indexer:
            assert indexer.total_lines == 3
            assert indexer.get_lines(2, 5) == [(3, "third-without-newline")]
    finally:
        os.unlink(path)


def test_empty_file():
    handle = tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False)
    path = handle.name
    handle.close()
    try:
        with MmapLogIndexer(path) as indexer:
            assert indexer.total_lines == 0
            assert indexer.get_lines(0, 10) == []
    finally:
        os.unlink(path)


def test_filters_and_key_matching(fifty_thousand_lines: str):
    from app.decoder_tree import build_tree
    from app.span_engine import WazuhSpanEngine

    full = WazuhSpanEngine(build_tree([("t.xml", r"""
    <decoder name="simple"><prematch>^line-</prematch></decoder>
    <decoder name="simple">
      <parent>simple</parent>
      <regex>^line-(\d+)\svalue=(\d+)</regex>
      <order>line_no,value</order>
    </decoder>""")]))
    root_only = WazuhSpanEngine(build_tree([("t.xml", '<decoder name="simple"><prematch>^line-</prematch></decoder>')]))

    with MmapLogIndexer(fifty_thousand_lines) as indexer:
        hits = indexer.search_and_filter_lines(full, "all", "value", 0, 3)
        assert [line.line_number for line in hits] == [1, 2, 3]
        assert all(not line.issues for line in hits)
        assert all(any(t.state == TokenState.CAPTURED for t in line.tokens) for line in hits)

        missing = indexer.search_and_filter_lines(root_only, "missing", "value", 100, 5, max_scan_lines=1000)
        assert [line.line_number for line in missing] == [101, 102, 103, 104, 105]
        assert all(line.decoder.name == "simple" for line in missing)
        assert indexer.search_and_filter_lines(full, "missing", None, 0, 5, max_scan_lines=1000) == []


def test_get_lines_is_bounded(fifty_thousand_lines: str):
    with MmapLogIndexer(fifty_thousand_lines) as indexer:
        assert indexer.get_lines(49_998, 100) == [
            (49_999, "line-049998 value=49998"),
            (50_000, "line-049999 value=49999"),
        ]
        assert indexer.get_lines(50_000, 10) == []
        assert indexer.get_lines(-15, 2) == [
            (1, "line-000000 value=0"),
            (2, "line-000001 value=1"),
        ]
