"""Cooperating writers serialize mutations per execution on local Linux storage."""

from __future__ import annotations

import asyncio
import os
import select
import stat
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aerlog.capture.normalizer import EventNormalizer
from aerlog.capture.pipeline import CaptureConfig, CapturePipeline
from aerlog.capture.sinks import RecoverySpool
from aerlog.events.ids import new_event_id, new_execution_id
from aerlog.events.models import ExecutionEvent, ExecutionHeader, ExecutionSummary
from aerlog.storage import (
    JsonlEventLogWriter,
    PersistentCaptureSink,
    RecordingRepository,
    TailPolicy,
)
from aerlog.storage.database import IndexedExecutionRow
from aerlog.storage.exceptions import ExecutionBusyError, StorageCorruptionError, StorageError
from aerlog.storage.ownership import ExecutionOwnership
from aerlog.storage.recovery_stage import RecoveryStage
from aerlog.storage.repositories import _VerifiedLog
from aerlog.storage.retention import RetentionPolicy, apply_retention


def test_same_id_busy_through_alias_and_borrowed_worker_handle(tmp_path: Path) -> None:
    root = tmp_path / "data"
    alias = tmp_path / "alias"
    alias.symlink_to(root)
    eid = new_execution_id()
    with ExecutionOwnership.acquire(root, eid) as owner:
        worker = owner.share(alias, eid)
        with pytest.raises(ValueError):
            owner.share(root, new_execution_id())
        with ThreadPoolExecutor(max_workers=1) as pool, pytest.raises(ExecutionBusyError):
            pool.submit(ExecutionOwnership.acquire, alias, eid).result(timeout=5)
        with ExecutionOwnership.acquire(alias, new_execution_id()):
            pass
    try:
        with pytest.raises(ExecutionBusyError, match="retry"):
            ExecutionOwnership.acquire(root, eid)
    finally:
        worker.close()
    lock = root / ".locks" / f"{eid}.lock"
    inode = lock.stat().st_ino
    with ExecutionOwnership.acquire(root, eid):
        assert lock.stat().st_ino == inode
        assert stat.S_IMODE(lock.stat().st_mode) == 0o600
        assert stat.S_IMODE(lock.parent.stat().st_mode) == 0o700


def test_killed_owner_releases_lock_for_next_process(tmp_path: Path) -> None:
    eid = new_execution_id()
    script = """
import signal, sys
from pathlib import Path
from aerlog.storage.ownership import ExecutionOwnership
with ExecutionOwnership.acquire(Path(sys.argv[1]), sys.argv[2]):
    print('ready', flush=True)
    signal.pause()
"""
    with subprocess.Popen(
        [sys.executable, "-c", script, str(tmp_path), eid], stdout=subprocess.PIPE
    ) as proc:
        try:
            assert proc.stdout is not None
            assert select.select([proc.stdout], [], [], 10)[0]
            assert proc.stdout.readline() == b"ready\n"
            with pytest.raises(ExecutionBusyError):
                ExecutionOwnership.acquire(tmp_path, eid)
        finally:
            proc.kill()
            proc.wait(timeout=5)
    with ExecutionOwnership.acquire(tmp_path, eid):
        pass


@pytest.mark.parametrize("kind", ["directory_link", "file_link", "fifo", "public", "hardlink"])
def test_unsafe_sidecars_refused_without_changing_other_files(tmp_path: Path, kind: str) -> None:
    eid = new_execution_id()
    root = tmp_path / "data"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    witness = outside / f"{eid}.lock"
    witness.write_bytes(b"keep")
    witness.chmod(0o644)
    locks = root / ".locks"
    sidecar = locks / witness.name
    if kind == "directory_link":
        locks.symlink_to(outside)
    else:
        locks.mkdir(mode=0o700)
        if kind == "file_link":
            sidecar.symlink_to(witness)
        elif kind == "fifo":
            os.mkfifo(sidecar)
        elif kind == "public":
            sidecar.touch(mode=0o644)
        else:
            os.link(witness, sidecar)
    with pytest.raises((OSError, StorageError)):
        ExecutionOwnership.acquire(root, eid)
    assert witness.read_bytes() == b"keep"
    assert stat.S_IMODE(witness.stat().st_mode) == 0o644


def test_writer_import_repair_reindex_and_cli_refuse_owner_before_mutation(tmp_path: Path) -> None:
    eid = new_execution_id()
    norm = EventNormalizer(
        execution_id=eid, started_at=datetime.now(UTC), monotonic_start_ns=1, command=("test",)
    )
    header = norm.build_header()
    spool = RecoverySpool(tmp_path / "source.spool")
    spool.write_events(norm.start_execution())
    spool.close()
    root = tmp_path / "data"
    repo = RecordingRepository(root)
    marker = tmp_path / "child"
    try:
        with ExecutionOwnership.acquire(root, eid):
            writer = JsonlEventLogWriter(root, eid)
            with pytest.raises(ExecutionBusyError):
                writer.open(header)
            with pytest.raises(ExecutionBusyError):
                repo.import_recovery_spool(spool.path)
            with pytest.raises(ExecutionBusyError):
                repo.recover_tail(eid)
            with pytest.raises(ExecutionBusyError):
                repo.reconcile_execution(eid)
            cli = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "aerlog",
                    "run",
                    "--quiet",
                    "--data-dir",
                    str(root),
                    "--execution-id",
                    eid,
                    "--",
                    sys.executable,
                    "-c",
                    "import pathlib,sys; pathlib.Path(sys.argv[1]).touch()",
                    str(marker),
                ],
                input=b"",
                capture_output=True,
                timeout=10,
                check=False,
            )
            assert cli.returncode == 1 and cli.stdout == b""
            assert b"busy" in cli.stderr and b"retry" in cli.stderr
            assert not marker.exists()
            assert {p.name for p in root.iterdir()} == {".locks"}
        assert repo.import_recovery_spool(spool.path).imported_events == 1
        assert repo.import_recovery_spool(spool.path).skipped_duplicates == 1
    finally:
        repo.close()


def _transcript(
    eid: str,
) -> tuple[EventNormalizer, ExecutionEvent, ExecutionEvent, ExecutionSummary]:
    norm = EventNormalizer(
        execution_id=eid, started_at=datetime.now(UTC), monotonic_start_ns=1, command=("test",)
    )
    (first,) = norm.start_execution()
    terminal, summary = norm.finalize_execution(
        ended_at=first.timestamp, monotonic_end_ns=2, termination_reason="clean_exit", exit_code=0
    )
    return norm, first, terminal, summary


def _write_transcript(path: Path, eid: str) -> tuple[ExecutionEvent, ExecutionEvent]:
    norm, first, terminal, summary = _transcript(eid)
    spool = RecoverySpool(path)
    try:
        spool.write_header(norm.build_header())
        spool.write_events([first, terminal])
        spool.write_summary(summary)
    finally:
        spool.close()
    return first, terminal


@pytest.mark.parametrize("checkpoint", ["preflight", "index"])
@pytest.mark.parametrize("policy", ["reject", "quarantine"])
def test_overlapping_imports_retry_against_committed_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, checkpoint: str, policy: TailPolicy
) -> None:
    root = tmp_path / "data"
    eid = new_execution_id()
    source = tmp_path / "winner.spool"
    first, terminal = _write_transcript(source, eid)
    contender = RecoverySpool(tmp_path / "loser.spool")
    contender.write_events([first.model_copy(update={"event_id": new_event_id()})])
    contender.close()
    ready, proceed = threading.Event(), threading.Event()
    winner, loser = RecordingRepository(root), RecordingRepository(root)
    other = new_execution_id()
    other_spool = tmp_path / "other.spool"
    _write_transcript(other_spool, other)

    def pause() -> None:
        ready.set()
        assert proceed.wait(10)

    if checkpoint == "index":
        original_replace = winner._replace_verified_index

        def gate_index(read: _VerifiedLog) -> None:
            pause()
            original_replace(read)

        monkeypatch.setattr(winner, "_replace_verified_index", gate_index)
    else:
        original_read = winner._read_recovery_destination

        def gate_read(execution_id: str, stage: RecoveryStage) -> _VerifiedLog:
            pause()
            return original_read(execution_id, stage)

        monkeypatch.setattr(winner, "_read_recovery_destination", gate_read)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            accepted = pool.submit(winner.import_recovery_spool, source)
            try:
                assert ready.wait(5)
                with pytest.raises(ExecutionBusyError):
                    loser.import_recovery_spool(contender.path, tail_policy=policy)
                with pytest.raises(ExecutionBusyError):
                    loser.recover_tail(eid)
                if checkpoint == "index" and policy == "reject":
                    probe = subprocess.run(
                        [
                            sys.executable,
                            "-c",
                            """
import sys
from pathlib import Path
from aerlog.storage import RecordingRepository, ExecutionBusyError
repo = RecordingRepository(Path(sys.argv[1]))
try:
    repo.import_recovery_spool(Path(sys.argv[2]))
except ExecutionBusyError:
    sys.exit(17)
finally:
    repo.close()
""",
                            str(root),
                            str(contender.path),
                        ],
                        capture_output=True,
                        timeout=5,
                        check=False,
                    )
                    assert probe.returncode == 17, probe.stderr
                assert loser.import_recovery_spool(other_spool).imported_events == 2
            finally:
                proceed.set()
            assert accepted.result(timeout=5).imported_events == 2
        if policy == "reject":
            with pytest.raises(StorageCorruptionError):
                loser.import_recovery_spool(contender.path, tail_policy=policy)
        else:
            rejected = loser.import_recovery_spool(contender.path, tail_policy=policy)
            assert rejected.corrupt_lines and rejected.imported_events == 0
        assert loser.import_recovery_spool(source).imported_events == 0
        read = loser.get_execution_events(eid, strict_integrity=True)
        assert [record.event.event_id for record in read.events] == [
            first.event_id,
            terminal.event_id,
        ]
        assert read.manifest is not None and read.manifest.line_count == 2
        row = loser.store.get_execution_row(eid)
        assert (
            row is not None
            and row.total_events == 2
            and row.jsonl_byte_offset == read.manifest.byte_size
        )
        indexed = loser.store.query_event_index(execution_id=eid)
        for index, item in zip(read.events, indexed, strict=True):
            assert item.event_id == index.event.event_id
            assert item.jsonl_byte_offset == index.byte_offset
    finally:
        proceed.set()
        winner.close()
        loser.close()


async def test_fallback_keeps_ownership_after_cancelled_close_waiter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    eid = new_execution_id()
    root = tmp_path / "data"
    sink = PersistentCaptureSink(root)
    entered, release = threading.Event(), threading.Event()

    def blocked_start(header: ExecutionHeader) -> None:
        entered.set()
        assert release.wait(10)
        raise OSError("primary unavailable")

    monkeypatch.setattr(sink, "_on_start_sync", blocked_start)
    pipeline = CapturePipeline(
        sink,
        command=("test",),
        execution_id=eid,
        config=CaptureConfig(
            backpressure_policy="spill", spill_dir=root / "spool", spill_write_timeout_s=0.05
        ),
    )
    repo = RecordingRepository(root)
    try:
        await pipeline.start()
        assert entered.is_set() and pipeline.spilled
        assert pipeline.spool_path is not None
        spool = pipeline.spool_path
        before = spool.read_bytes()
        with pytest.raises(ExecutionBusyError):
            repo.import_recovery_spool(spool)
        second_sink = PersistentCaptureSink(root)
        second = CapturePipeline(
            second_sink, command=("other",), execution_id=eid, config=pipeline.config
        )
        with pytest.raises(ExecutionBusyError):
            await second.start()
        assert spool.read_bytes() == before
        close_started = asyncio.Event()
        original_close = sink.close

        async def report_close() -> None:
            close_started.set()
            await original_close()

        monkeypatch.setattr(sink, "close", report_close)
        closing = asyncio.create_task(
            pipeline.finalize(termination_reason="clean_exit", exit_code=0)
        )
        await asyncio.wait_for(close_started.wait(), 5)
        closing.cancel()
        await asyncio.sleep(0)
        closing.cancel()
        with pytest.raises(asyncio.CancelledError):
            await closing
        assert not pipeline._spool.is_open and not sink.closed
        with pytest.raises(ExecutionBusyError):
            repo.import_recovery_spool(spool)
        release.set()
        await asyncio.wait_for(sink.close(), 5)
        if pipeline._close_task is not None:
            await pipeline._close_task
        assert repo.import_recovery_spool(spool).imported_events > 0
    finally:
        release.set()
        await sink.close()
        repo.close()


def test_bulk_repair_retention_and_missing_marking_report_only_completed_work(
    tmp_path: Path,
) -> None:
    root = tmp_path / "data"
    busy, free = new_execution_id(), new_execution_id()
    repo = RecordingRepository(root)
    try:
        for eid in (busy, free):
            source = tmp_path / f"{eid}.spool"
            _write_transcript(source, eid)
            repo.import_recovery_spool(source)
        with ExecutionOwnership.acquire(root, busy):
            bulk = repo.reconcile_all_executions()
            assert bulk.busy_execution_ids == (busy,) and bulk.reconciled_execution_ids == (free,)
            report = apply_retention(
                root, repo.store, RetentionPolicy(max_executions=0, dry_run=False), confirm=True
            )
            assert report.busy_execution_ids == (busy,) and report.deleted_execution_ids == (free,)
            assert not (root / "executions" / free).exists()
        # Simulate an execution directory lost outside AERLOG. Re-read under ownership
        # before marking that loss, both in the query path and bulk reconciliation.
        (root / "executions" / busy).rename(tmp_path / "missing")
        before = repo.store.get_execution_row(busy)
        assert before is not None
        with ExecutionOwnership.acquire(root, busy):
            with pytest.raises(ExecutionBusyError):
                repo.get_execution_events(busy)
            bulk = repo.reconcile_all_executions()
            assert bulk.busy_execution_ids == (busy,) and not bulk.missing_jsonl_execution_ids
            assert before == repo.store.get_execution_row(busy)
        assert repo.reconcile_all_executions().missing_jsonl_execution_ids == (busy,)
    finally:
        repo.close()


def test_confirmed_retention_rechecks_snapshot_after_execution_becomes_protected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "data"
    eid = new_execution_id()
    repo = RecordingRepository(root)
    source = tmp_path / "source.spool"
    _write_transcript(source, eid)
    try:
        repo.import_recovery_spool(source)
        original = repo.store.list_execution_rows
        snapshot_taken = False

        def changed_after_snapshot(*, limit: int, offset: int) -> tuple[IndexedExecutionRow, ...]:
            nonlocal snapshot_taken
            snapshot = original(limit=limit, offset=offset)
            if not snapshot_taken:
                snapshot_taken = True
                with ExecutionOwnership.acquire(root, eid):
                    repo.store.insert_execution_start(_transcript(eid)[0].build_header())
            return snapshot

        monkeypatch.setattr(repo.store, "list_execution_rows", changed_after_snapshot)
        report = apply_retention(
            root, repo.store, RetentionPolicy(max_executions=0, dry_run=False), confirm=True
        )
        assert report.candidate_execution_ids == (eid,) and report.protected_execution_ids == (eid,)
        assert not report.deleted_execution_ids and report.reclaimed_bytes == 0
        assert (root / "executions" / eid / "events.jsonl").exists()
    finally:
        repo.close()


async def test_standalone_sink_owns_until_worker_close_and_refuses_recording_reuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    eid = new_execution_id()
    norm, *_ = _transcript(eid)
    sink = PersistentCaptureSink(tmp_path)
    await sink.on_start(norm.build_header())
    original_close = sink.store.close
    entered, release = threading.Event(), threading.Event()

    def gate_close() -> None:
        entered.set()
        assert release.wait(10)
        original_close()

    monkeypatch.setattr(sink.store, "close", gate_close)
    closing = asyncio.create_task(sink.close())
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        closing.cancel()
        with pytest.raises(asyncio.CancelledError):
            await closing
        with pytest.raises(ExecutionBusyError):
            ExecutionOwnership.acquire(tmp_path, eid)
    finally:
        release.set()
        await sink.close()
    second = PersistentCaptureSink(tmp_path)
    try:
        with pytest.raises(ValueError, match="already exists"):
            await second.on_start(norm.build_header())
    finally:
        await second.close()
    with ExecutionOwnership.acquire(tmp_path, eid):
        pass


async def test_competing_pipeline_cannot_close_the_first_pipelines_sink(tmp_path: Path) -> None:
    eid = new_execution_id()
    sink = PersistentCaptureSink(tmp_path)
    first = CapturePipeline(sink, command=("first",), execution_id=eid)
    second = CapturePipeline(sink, command=("second",), execution_id=eid)
    try:
        await first.start()
        with pytest.raises(ExecutionBusyError):
            await second.start()
        assert not sink.closed
        with pytest.raises(ExecutionBusyError):
            ExecutionOwnership.acquire(tmp_path, eid)
        assert (
            await first.finalize(termination_reason="clean_exit", exit_code=0)
        ).capture_completeness == "complete"
    finally:
        await first.finalize(termination_reason="clean_exit", exit_code=0)
        await sink.close()
