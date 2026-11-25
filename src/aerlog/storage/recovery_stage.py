"""Private, disposable staging for verified recovery imports."""

from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Generator, Iterator
from contextlib import closing, contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Literal

from aerlog.events.models import ExecutionEvent
from aerlog.storage.event_log import IndexedLogEvent


class RecoveryStage:
    """Keep validated spool records and destination identities out of the Python heap."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection
        connection.executescript("""
            PRAGMA page_size = 8192;
            PRAGMA journal_mode = OFF;
            PRAGMA cache_size = -2048;
            PRAGMA temp_store = FILE;
            CREATE TABLE spool (
                ordinal INTEGER PRIMARY KEY,
                event TEXT NOT NULL,
                legacy_strict INTEGER NOT NULL
            );
            CREATE TABLE log (
                ordinal INTEGER PRIMARY KEY,
                event_id TEXT NOT NULL,
                sequence TEXT NOT NULL,
                event TEXT NOT NULL,
                explicit_id INTEGER NOT NULL,
                terminal INTEGER NOT NULL,
                line_number INTEGER NOT NULL,
                byte_offset INTEGER NOT NULL,
                byte_length INTEGER NOT NULL
            );
            CREATE INDEX log_event_id ON log(event_id);
            CREATE INDEX log_sequence ON log(sequence);
            CREATE TABLE candidates (
                spool_ordinal INTEGER PRIMARY KEY,
                event_id TEXT NOT NULL UNIQUE,
                sequence TEXT NOT NULL UNIQUE
            );
            CREATE INDEX candidate_order ON candidates(length(sequence), sequence);
            """)
        self.log = _StagedLog(connection)

    def add_spool_event(self, event: ExecutionEvent, legacy_strict: bool) -> None:
        self._connection.execute(
            "INSERT INTO spool (event, legacy_strict) VALUES (?, ?)",
            (_encode_event(event), legacy_strict),
        )

    def spool_events(self) -> Iterator[tuple[int, ExecutionEvent, bool]]:
        cursor = self._connection.execute(
            "SELECT ordinal, event, legacy_strict FROM spool ORDER BY ordinal"
        )
        for ordinal, payload, legacy_strict in cursor:
            yield ordinal, _decode_event(payload), bool(legacy_strict)

    def spool_event_for_quarantine(self, ordinal: int) -> Iterator[ExecutionEvent]:
        (payload,) = self._connection.execute(
            "SELECT event FROM spool WHERE ordinal = ?", (ordinal,)
        ).fetchone()
        yield _decode_event(payload)

    def reset_log(self) -> None:
        self._connection.execute("DELETE FROM log")

    def add_log_event(self, item: IndexedLogEvent) -> None:
        event = item.event
        self._connection.execute(
            """
            INSERT INTO log (event_id, sequence, event, explicit_id, terminal,
                             line_number, byte_offset, byte_length)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.event_id,
                str(event.sequence),
                _encode_event(event),
                "event_id" in event.model_fields_set and bool(event.event_id.strip()),
                event.kind == "execution_finished",
                item.line_number,
                item.byte_offset,
                item.byte_length,
            ),
        )

    def log_has_terminal(self) -> bool:
        return (
            self._connection.execute("SELECT 1 FROM log WHERE terminal LIMIT 1").fetchone()
            is not None
        )

    def remove_last_log_event(self) -> None:
        self._connection.execute("DELETE FROM log WHERE ordinal = (SELECT max(ordinal) FROM log)")

    def find_ambiguous_log_identity(self) -> int | None:
        row = self._connection.execute(
            """
            SELECT sequence FROM log AS item
            WHERE NOT explicit_id OR EXISTS (SELECT 1 FROM log
                          WHERE event_id = item.event_id AND ordinal < item.ordinal)
               OR EXISTS (SELECT 1 FROM log
                          WHERE sequence = item.sequence AND ordinal < item.ordinal)
            ORDER BY ordinal LIMIT 1
            """
        ).fetchone()
        return int(row[0]) if row is not None else None

    def find_log_or_candidate(
        self, event: ExecutionEvent
    ) -> tuple[ExecutionEvent | None, ExecutionEvent | None]:
        by_id = self._find_identity("event_id", event.event_id)
        if by_id is not None and by_id.sequence == event.sequence:
            return by_id, by_id
        return by_id, self._find_identity("sequence", str(event.sequence))

    def _find_identity(
        self, column: Literal["event_id", "sequence"], value: str
    ) -> ExecutionEvent | None:
        row = self._connection.execute(
            f"""
            SELECT event FROM log WHERE {column} = ?
            UNION ALL
            SELECT spool.event FROM candidates
            JOIN spool ON spool.ordinal = candidates.spool_ordinal
            WHERE candidates.{column} = ?
            LIMIT 1
            """,
            (value, value),
        ).fetchone()
        return _decode_event(row[0]) if row is not None else None

    def add_candidate(self, ordinal: int, event: ExecutionEvent) -> None:
        self._connection.execute(
            "INSERT INTO candidates VALUES (?, ?, ?)",
            # Event sequences can exceed SQLite's signed 64-bit INTEGER range.
            (ordinal, event.event_id, str(event.sequence)),
        )

    def candidates(
        self, *, offset: int = 0, limit: int = -1
    ) -> Generator[ExecutionEvent, None, None]:
        cursor = self._connection.execute(
            """
            SELECT spool.event FROM candidates
            JOIN spool ON spool.ordinal = candidates.spool_ordinal
            ORDER BY length(candidates.sequence), candidates.sequence LIMIT ? OFFSET ?
            """,
            (limit, offset),
        )
        for (payload,) in cursor:
            yield _decode_event(payload)


def _encode_event(event: ExecutionEvent) -> str:
    # Match the recorder's JSON representation, including non-finite values in raw payloads.
    return json.dumps(event.model_dump(mode="json"), separators=(",", ":"))


def _decode_event(payload: str) -> ExecutionEvent:
    return ExecutionEvent.model_validate(json.loads(payload))


class _StagedLog:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    def __len__(self) -> int:
        (count,) = self._connection.execute("SELECT count(*) FROM log").fetchone()
        return int(count)

    def __getitem__(self, index: int) -> IndexedLogEvent:
        if index < 0:
            index += len(self)
        if index < 0:
            raise IndexError(index)
        row = self._connection.execute(
            "SELECT event, line_number, byte_offset, byte_length FROM log WHERE ordinal = ?",
            (index + 1,),
        ).fetchone()
        if row is None:
            raise IndexError(index)
        payload, line_number, byte_offset, byte_length = row
        return IndexedLogEvent(
            _decode_event(payload),
            line_number,
            byte_offset,
            byte_length,
        )

    def __iter__(self) -> Iterator[IndexedLogEvent]:
        cursor = self._connection.execute(
            "SELECT event, line_number, byte_offset, byte_length FROM log ORDER BY ordinal"
        )
        for payload, line_number, byte_offset, byte_length in cursor:
            yield IndexedLogEvent(_decode_event(payload), line_number, byte_offset, byte_length)


@contextmanager
def stage_recovery() -> Iterator[RecoveryStage]:
    """Place scratch files inside a private directory and clean up on every exit."""
    with TemporaryDirectory(prefix="aerlog-recovery-") as temporary:
        path = Path(temporary) / "stage.sqlite3"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        with closing(sqlite3.connect(path)) as connection:
            yield RecoveryStage(connection)
