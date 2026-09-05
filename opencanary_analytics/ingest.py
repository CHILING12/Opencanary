"""Robust JSONL ingestion with checkpoint and rotation handling."""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

from .models import NormalizedEvent, ProcessResult
from .normalize import parse_line
from .storage import SQLiteStore


@dataclass
class IngestStats:
    lines: int = 0
    parsed: int = 0
    malformed: int = 0
    duplicates: int = 0
    accepted: int = 0


@dataclass(frozen=True)
class ParseResult:
    event: NormalizedEvent | None
    error: str | None = None


@dataclass(frozen=True)
class TailRecord:
    line: bytes
    path: str
    inode: int
    start_offset: int
    end_offset: int


def parse_result(line: str | bytes, hmac_key: bytes) -> ParseResult:
    try:
        return ParseResult(parse_line(line, hmac_key))
    except (TypeError, ValueError) as exc:
        # Do not include the input line in errors: it can contain credentials.
        return ParseResult(None, str(exc) or "invalid event")


class FileTailer:
    """Read complete JSONL records while surviving rotation and truncation.

    ``read_records`` returns records that must be acknowledged after durable
    processing.  The compatibility ``read_available`` method acknowledges
    records immediately and should only be used when downstream processing
    cannot fail.  Local and durable cursors are separate, so a partial line is
    never appended repeatedly across polls.
    """

    def __init__(self, path: str | Path, store: SQLiteStore, chunk_size: int = 65536):
        self.path = str(Path(path).expanduser())
        self.store = store
        self.chunk_size = max(1, int(chunk_size))
        self._buffer = b""
        self._buffer_start = 0
        self._inode: int | None = None
        self._read_offset = 0
        self._committed_offset = 0
        self._pending: list[TailRecord] = []
        self._load_checkpoint()

    def _load_checkpoint(self) -> None:
        inode, offset = self.store.checkpoint(self.path)
        self._inode = inode
        self._read_offset = offset
        self._committed_offset = offset
        self._buffer_start = offset

    def _reset_for_file(self, inode: int) -> None:
        self._inode = inode
        self._read_offset = 0
        self._committed_offset = 0
        self._buffer_start = 0
        self._buffer = b""
        self._pending.clear()

    def read_records(self) -> list[TailRecord]:
        """Return complete, not-yet-acknowledged records currently available."""
        try:
            stat = os.stat(self.path)
        except FileNotFoundError:
            return list(self._pending)
        inode = stat.st_ino
        if self._pending:
            return list(self._pending)
        if self._inode != inode or stat.st_size < self._read_offset:
            self._reset_for_file(inode)

        records: list[TailRecord] = []
        while True:
            with open(self.path, "rb") as handle:
                handle.seek(self._read_offset)
                data = handle.read(self.chunk_size)
            if not data:
                break
            self._read_offset += len(data)
            if not self._buffer:
                self._buffer_start = self._read_offset - len(data)
            self._buffer += data
            parts = self._buffer.split(b"\n")
            self._buffer = parts.pop()
            cursor = self._buffer_start
            for line in parts:
                end = cursor + len(line) + 1
                if line.strip():
                    records.append(TailRecord(line, self.path, inode, cursor, end))
                cursor = end
            self._buffer_start = cursor
            if len(data) < self.chunk_size:
                break
        self._pending.extend(records)
        return list(self._pending)

    def acknowledge(self, record: TailRecord) -> None:
        """Persist a record's end offset after processing succeeds."""
        if record.path != self.path or record.inode != self._inode:
            raise ValueError("record does not belong to this tailer generation")
        if not self._pending or self._pending[0] != record:
            raise ValueError("records must be acknowledged in source order")
        self._pending.pop(0)
        self._committed_offset = record.end_offset
        self.store.save_checkpoint(self.path, record.inode, record.end_offset)

    def read_available(self) -> list[bytes]:
        """Compatibility wrapper returning and immediately acknowledging lines."""
        records = self.read_records()
        lines = [record.line for record in records]
        for record in records:
            self.acknowledge(record)
        return lines

    def poll_records(self, interval: float = 0.5) -> Iterator[TailRecord]:
        while True:
            records = self.read_records()
            if records:
                for record in records:
                    yield record
                    # A consumer that uses this compatibility generator is
                    # expected to process one record before requesting next.
                    if self._pending and self._pending[0] == record:
                        self.acknowledge(record)
            else:
                time.sleep(interval)

    def poll(self, interval: float = 0.5) -> Iterator[bytes]:
        """Compatibility polling iterator yielding bytes after safe ack."""
        for record in self.poll_records(interval):
            yield record.line


def ingest_file(
    path: str | Path,
    store: SQLiteStore,
    hmac_key: bytes,
    handler: Callable[[NormalizedEvent], bool | ProcessResult] | None = None,
) -> IngestStats:
    """Import all complete records from a file once, acknowledging after work."""
    tailer = FileTailer(path, store)
    stats = IngestStats()
    for record in tailer.read_records():
        stats.lines += 1
        result = parse_result(record.line, hmac_key)
        if result.event is None:
            stats.malformed += 1
            store.increment("events_malformed")
            tailer.acknowledge(record)
            continue
        stats.parsed += 1
        outcome: bool | ProcessResult
        if handler is None:
            outcome = store.add_event(result.event)
        else:
            outcome = handler(result.event)
        if isinstance(outcome, ProcessResult):
            accepted = outcome.accepted
            duplicate = outcome.duplicate
        else:
            accepted = bool(outcome)
            duplicate = not accepted
        if accepted:
            stats.accepted += 1
        if duplicate:
            stats.duplicates += 1
        # Parsing and handler completion have both succeeded; only now can the
        # source position be acknowledged durably.
        tailer.acknowledge(record)
    return stats
