"""Memory-mapped, sparse-index log reader.

Never calls ``read()`` or ``readlines()`` on the log.  The file is mapped with
``mmap`` and a sparse offset table is built for every N-th line (default
1,000).  Random access jumps straight to the nearest sampled offset and walks
at most N newline bytes, so a 20 GB archive costs a handful of megabytes of
Python memory.
"""
from __future__ import annotations

import mmap
import os
import threading
from typing import Iterator, List, Optional, Sequence, Tuple

from .schemas import AnalyzedLine


class MmapLogIndexer:
    DEFAULT_SAMPLE_INTERVAL = 1000
    SCAN_CHUNK_BYTES = 16 * 1024 * 1024
    READ_BATCH_LINES = 2000

    def __init__(self, path: str, sample_interval: int = DEFAULT_SAMPLE_INTERVAL):
        if sample_interval < 1:
            raise ValueError("sample_interval must be >= 1")
        self.path = os.path.abspath(path)
        self.sample_interval = sample_interval
        self._fd = os.open(self.path, os.O_RDONLY)
        self.file_size_bytes = os.path.getsize(self.path)
        if self.file_size_bytes == 0:
            # mmap.mmap(fd, 0) raises on an empty file; keep the descriptor for
            # symmetry and let every reader short-circuit on total_lines == 0.
            self._mm: Optional[mmap.mmap] = None
        else:
            try:
                self._mm = mmap.mmap(self._fd, 0, access=mmap.ACCESS_READ)
            except Exception:
                os.close(self._fd)
                raise
        self.sparse_offsets: List[int] = []
        self.total_lines = 0
        self._lock = threading.RLock()
        self._closed = False
        self._scan_index()

    # ------------------------------------------------------------------ index
    def _scan_index(self) -> None:
        size = self.file_size_bytes
        if size == 0 or self._mm is None:
            self.sparse_offsets = []
            self.total_lines = 0
            return

        offsets: List[int] = [0]
        line_count = 0
        pos = 0
        chunk = self.SCAN_CHUNK_BYTES
        newline = b"\n"
        while pos < size:
            chunk_end = min(pos + chunk, size)
            nl = self._mm.find(newline, pos, chunk_end)
            if nl == -1:
                pos = chunk_end
                continue
            line_count += 1
            pos = nl + 1
            if line_count % self.sample_interval == 0 and pos < size:
                offsets.append(pos)

        if self._mm[size - 1:size] != b"\n":
            line_count += 1

        self.sparse_offsets = offsets
        self.total_lines = line_count

    # ------------------------------------------------------------- primitives
    def _locate(self, start_line: int) -> int:
        """Return the byte offset of 0-based ``start_line`` (or EOF)."""
        if start_line <= 0:
            return 0
        assert self._mm is not None
        if start_line >= self.total_lines:
            return self.file_size_bytes
        block = start_line // self.sample_interval
        if block >= len(self.sparse_offsets):
            block = len(self.sparse_offsets) - 1
        pos = self.sparse_offsets[block]
        line = block * self.sample_interval
        while line < start_line:
            nl = self._mm.find(b"\n", pos)
            if nl == -1:
                return self.file_size_bytes
            pos = nl + 1
            line += 1
        return pos

    def _read_at(self, pos: int) -> Tuple[str, int]:
        """Read one line at ``pos``; return (text, next_pos)."""
        assert self._mm is not None
        nl = self._mm.find(b"\n", pos)
        end = self.file_size_bytes if nl == -1 else nl
        raw = self._mm[pos:end]
        if raw.endswith(b"\r"):
            raw = raw[:-1]
        text = raw.decode("utf-8", errors="replace")
        return text, (self.file_size_bytes if nl == -1 else nl + 1)

    # ------------------------------------------------------------ public APIs
    def get_lines(self, start_line: int, limit: int) -> List[Tuple[int, str]]:
        """Return ``[(1-based line number, text), ...]`` starting at 0-based index."""
        if limit <= 0 or self.total_lines == 0:
            return []
        start_line = max(0, start_line)
        if start_line >= self.total_lines:
            return []
        result: List[Tuple[int, str]] = []
        with self._lock:
            self._ensure_open()
            pos = self._locate(start_line)
            line_no = start_line + 1
            count = 0
            while count < limit and pos < self.file_size_bytes:
                if line_no > self.total_lines:
                    break
                text, next_pos = self._read_at(pos)
                result.append((line_no, text))
                count += 1
                line_no += 1
                if next_pos <= pos:
                    break
                pos = next_pos
        return result

    def iter_lines(
        self, start_line: int = 0, limit: Optional[int] = None
    ) -> Iterator[Tuple[int, str]]:
        """Yield lines sequentially using bounded batches (never loads the file)."""
        if limit is None:
            limit = max(0, self.total_lines - start_line)
        if limit <= 0 or start_line >= self.total_lines:
            return
        produced = 0
        cursor = max(0, start_line)
        while produced < limit:
            batch_size = min(self.READ_BATCH_LINES, limit - produced)
            batch = self.get_lines(cursor, batch_size)
            if not batch:
                return
            for item in batch:
                yield item
            produced += len(batch)
            cursor += len(batch)

    @staticmethod
    def _matches(line: AnalyzedLine, filter_mode: str, target_key: Optional[str]) -> bool:
        key = (target_key or "").lower()
        kinds = {
            "all": None,
            "missing": ("missing", "json", "value"),
            "broken": ("broken",),
        }
        if filter_mode == "no_decoder":
            return line.status != "decoded"
        if filter_mode not in kinds:
            raise ValueError(f"unknown filter_mode: {filter_mode}")
        wanted = kinds[filter_mode]
        issues = [i for i in line.issues if wanted is None or i.kind in wanted]
        if not key:
            return wanted is None or bool(issues)
        names = [(i.key or i.value_kind or "").lower() for i in issues]
        if wanted is None:
            names += [f.name.lower() for f in line.fields]
        return key in names

    def search_and_filter_lines(
        self,
        engine,
        filter_mode: str,
        target_key: Optional[str],
        start_line: int,
        limit: int,
        max_scan_lines: Optional[int] = None,
    ) -> List[AnalyzedLine]:
        """Stream from ``start_line`` until ``limit`` matching lines are collected."""
        if limit <= 0 or start_line >= self.total_lines:
            return []
        scan_limit = self.total_lines - start_line
        if max_scan_lines is not None:
            scan_limit = min(scan_limit, max(0, max_scan_lines))
        matches: List[AnalyzedLine] = []
        for line_no, text in self.iter_lines(start_line, scan_limit):
            # Cheap pass to filter; full detail (tokens, trace, fixes) only for the lines returned.
            if self._matches(engine.analyze(text, line_no, detail=False), filter_mode, target_key):
                matches.append(engine.analyze(text, line_no))
                if len(matches) >= limit:
                    break
        return matches

    # ---------------------------------------------------------------- lifecycle
    def _ensure_open(self) -> None:
        if self._closed:
            raise ValueError("mmap indexer is closed")

    def close(self) -> None:
        with getattr(self, "_lock", threading.RLock()):
            if getattr(self, "_closed", True):
                return
            self._closed = True
            try:
                if self._mm is not None:
                    self._mm.close()
            finally:
                try:
                    os.close(self._fd)
                except OSError:
                    pass

    def __enter__(self) -> "MmapLogIndexer":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __del__(self):  # pragma: no cover - defensive cleanup
        try:
            self.close()
        except Exception:
            pass

    def stats(self) -> dict:
        return {
            "path": self.path,
            "file_size_bytes": self.file_size_bytes,
            "total_lines": self.total_lines,
        }
