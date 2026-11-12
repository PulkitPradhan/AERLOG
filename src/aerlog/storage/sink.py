"""Persistent CaptureSink writing authoritative JSONL logs and SQLite index entries."""

from __future__ import annotations

import asyncio
import concurrent.futures
import threading
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from aerlog.events.models import ExecutionEvent, ExecutionHeader, ExecutionSummary
from aerlog.events.types import RedactionMode
from aerlog.storage.database import SQLiteMetadataStore, SqliteSynchronousMode
from aerlog.storage.event_log import FsyncPolicy, JsonlEventLogWriter
from aerlog.storage.exceptions import StorageWriteError


class PersistentCaptureSink:
    """Implements ``CaptureSink`` over ``events.jsonl`` and ``aerlog.db``."""

    def __init__(
        self,
        data_dir: Path,
        *,
        store: SQLiteMetadataStore | None = None,
        fsync_policy: FsyncPolicy = "lifecycle",
        sqlite_synchronous: SqliteSynchronousMode = "NORMAL",
        redaction_mode: RedactionMode = "standard",
        persist_cwd: bool = False,
    ) -> None:
        self._data_dir = data_dir
        self._owns_store = store is None
        self._store = (
            SQLiteMetadataStore(
                data_dir,
                synchronous=sqlite_synchronous,
                persist_cwd=persist_cwd,
            )
            if store is None
            else store
        )
        self._fsync_policy: FsyncPolicy = fsync_policy
        self._redaction_mode: RedactionMode = redaction_mode
        self._persist_cwd = persist_cwd

        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="aerlog-sink",
        )
        self._state_lock = threading.Lock()
        self._close_requested = False
        self._closed = False
        self._close_future: asyncio.Future[None] | None = None

        self._writer: JsonlEventLogWriter | None = None
        self._execution_id: str | None = None
        self._sqlite_diverged = False

    @property
    def execution_id(self) -> str | None:
        """Execution identifier for the currently active recording, if started."""
        return self._execution_id

    @property
    def sqlite_diverged(self) -> bool:
        """True if JSONL writes succeeded while an SQLite index write failed."""
        return self._sqlite_diverged

    @property
    def store(self) -> SQLiteMetadataStore:
        """Underlying SQLite metadata store."""
        return self._store

    @property
    def closed(self) -> bool:
        """True if the sink has completed closure."""
        with self._state_lock:
            return self._closed

    def _mark_closed(self) -> None:
        with self._state_lock:
            self._closed = True

    def _submit_op(self, method_name: str, *args: Any) -> asyncio.Future[Any]:
        with self._state_lock:
            if self._closed or self._close_requested:
                raise StorageWriteError(
                    f"Cannot execute {method_name}(): sink is closed or closing"
                )

            def _runner() -> Any:
                target = getattr(self, method_name)
                return target(*args)

            cf_future = self._executor.submit(_runner)

        loop = asyncio.get_running_loop()
        return asyncio.wrap_future(cf_future, loop=loop)

    def _on_start_sync(self, header: ExecutionHeader) -> None:
        self._store.initialize()
        if (
            header.redaction_mode != self._redaction_mode
            and self._redaction_mode != "explicit_unredacted"
        ):
            raise StorageWriteError(
                f"Sink redaction_mode {self._redaction_mode!r} cannot accept header with "
                f"{header.redaction_mode!r}"
            )
        writer = JsonlEventLogWriter(
            self._data_dir,
            header.execution_id,
            fsync_policy=self._fsync_policy,
            redaction_mode=self._redaction_mode,
            persist_cwd=self._persist_cwd,
        )
        writer.open(header)
        self._writer = writer
        self._execution_id = header.execution_id
        try:
            self._store.insert_execution_start(header)
        except Exception:
            self._sqlite_diverged = True
            raise

    def _emit_events_sync(self, events: Sequence[ExecutionEvent]) -> None:
        if not events:
            return
        if self._writer is None or self._execution_id is None:
            raise StorageWriteError("PersistentCaptureSink.on_start() must precede emit_events()")
        slices = self._writer.append_events(events)
        try:
            self._store.insert_event_slices(self._execution_id, slices)
        except Exception:
            self._sqlite_diverged = True
            raise

    def _on_finish_sync(self, summary: ExecutionSummary) -> None:
        if self._writer is None or self._execution_id is None:
            raise StorageWriteError("PersistentCaptureSink.on_start() must precede on_finish()")
        manifest = self._writer.finalize(summary)
        try:
            self._store.update_execution_finish(
                summary,
                jsonl_byte_offset=manifest.byte_size,
                jsonl_sha256=manifest.events_file_sha256,
                index_status="diverged" if self._sqlite_diverged else "indexed",
            )
        except Exception:
            self._sqlite_diverged = True
            raise

    def _flush_sync(self) -> None:
        if self._writer is not None:
            self._writer.flush()

    def _close_sync(self) -> None:
        errors: list[Exception] = []
        try:
            if self._writer is not None:
                try:
                    self._writer.close()
                except Exception as exc:
                    errors.append(exc)
                finally:
                    self._writer = None
        finally:
            try:
                if self._owns_store:
                    self._store.close()
            except Exception as exc:
                errors.append(exc)
            finally:
                self._executor.shutdown(wait=False)

        if len(errors) == 1:
            raise errors[0]
        if errors:
            raise ExceptionGroup("PersistentCaptureSink.close failed", errors)

    async def on_start(self, header: ExecutionHeader) -> None:
        """Initialize execution log files and insert initial ``executions`` index row."""
        await self._submit_op("_on_start_sync", header)

    async def emit_events(self, events: Sequence[ExecutionEvent]) -> None:
        """Append redacted events to JSONL first, then commit SQLite index rows."""
        await self._submit_op("_emit_events_sync", events)

    async def on_finish(self, summary: ExecutionSummary) -> None:
        """Finalize atomic summary/manifest metadata and SQLite execution status."""
        await self._submit_op("_on_finish_sync", summary)

    async def flush(self) -> None:
        """Flush buffered JSONL writes according to configured fsync policy."""
        await self._submit_op("_flush_sync")

    async def close(self) -> None:
        """Close owned JSONL and SQLite handles cleanly."""
        fut: asyncio.Future[None]
        with self._state_lock:
            if self._closed and self._close_future is not None and self._close_future.done():
                exc = self._close_future.exception()
                if exc is not None:
                    raise exc
                return
            if self._close_future is not None:
                fut = self._close_future
            else:
                self._close_requested = True
                loop = asyncio.get_running_loop()

                def _close_runner() -> None:
                    target = self._close_sync
                    target()

                cf_future = self._executor.submit(_close_runner)
                fut = asyncio.wrap_future(cf_future, loop=loop)
                fut.add_done_callback(lambda _f: self._mark_closed())
                self._close_future = fut

        await asyncio.shield(fut)


__all__ = ["PersistentCaptureSink"]
