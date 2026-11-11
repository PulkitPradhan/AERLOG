"""Explicit, safety-guarded retention evaluation and SQLite compaction helpers.

Safety guarantees:
    - Retention defaults to ``dry_run=True`` and never runs automatically during capture.
    - Active ``'recording'`` executions are always protected from deletion.
    - Destructive deletion requires both ``policy.dry_run=False`` and ``confirm=True``.
    - Finalized ``events.jsonl`` logs are never rewritten in place.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from aerlog.storage.database import IndexedExecutionRow, SQLiteMetadataStore
from aerlog.storage.event_log import resolve_execution_dir

_PROTECTED_INCOMPLETE_STATUSES = frozenset({"incomplete", "spilled", "degraded", "corrupted"})


@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    """Minimal retention thresholds defaulting to non-destructive ``dry_run=True``."""

    max_executions: int | None = None
    max_age_days: int | None = None
    max_total_bytes: int | None = None
    protect_incomplete: bool = True
    dry_run: bool = True

    def __post_init__(self) -> None:
        if self.max_executions is not None and self.max_executions < 0:
            raise ValueError("max_executions must be non-negative")
        if self.max_age_days is not None and self.max_age_days < 0:
            raise ValueError("max_age_days must be non-negative")
        if self.max_total_bytes is not None and self.max_total_bytes < 0:
            raise ValueError("max_total_bytes must be non-negative")


@dataclass(frozen=True, slots=True)
class RetentionReport:
    """Summary of evaluated or applied retention pruning."""

    dry_run: bool
    candidate_execution_ids: tuple[str, ...]
    deleted_execution_ids: tuple[str, ...]
    protected_execution_ids: tuple[str, ...]
    reclaimed_bytes: int
    compacted: bool


def _execution_dir_bytes(data_dir: Path, execution_id: str) -> int:
    exec_dir = resolve_execution_dir(data_dir, execution_id)
    if not exec_dir.exists():
        return 0
    total = 0
    for child in exec_dir.rglob("*"):
        if child.is_file() and not child.is_symlink():
            total += child.stat().st_size
    return total


def _is_protected(row: IndexedExecutionRow, *, protect_incomplete: bool) -> bool:
    if row.capture_completeness == "recording":
        return True
    return protect_incomplete and row.capture_completeness in _PROTECTED_INCOMPLETE_STATUSES


def apply_retention(
    data_dir: Path,
    store: SQLiteMetadataStore,
    policy: RetentionPolicy,
    *,
    confirm: bool = False,
    vacuum: bool = False,
    now: datetime | None = None,
) -> RetentionReport:
    """Evaluate retention rules or prune eligible recordings with explicit confirmation."""
    if not policy.dry_run and not confirm:
        raise ValueError("Destructive retention deletion requires confirm=True")

    store.initialize()
    ref_now = datetime.now(UTC) if now is None else now.astimezone(UTC)
    rows = store.list_execution_rows(limit=1_000_000, offset=0)  # newest first

    protected_ids: list[str] = []
    eligible: list[tuple[IndexedExecutionRow, int]] = []
    total_dir_bytes = 0

    for row in rows:
        size = _execution_dir_bytes(data_dir, row.execution_id)
        total_dir_bytes += size
        if _is_protected(row, protect_incomplete=policy.protect_incomplete):
            protected_ids.append(row.execution_id)
        else:
            eligible.append((row, size))

    to_delete_ids: set[str] = set()
    to_delete_order: list[str] = []
    size_by_id = {row.execution_id: size for row, size in eligible}

    def _mark(eid: str) -> None:
        if eid not in to_delete_ids:
            to_delete_ids.add(eid)
            to_delete_order.append(eid)

    if policy.max_age_days is not None:
        cutoff = ref_now - timedelta(days=policy.max_age_days)
        for row, _ in reversed(eligible):
            ref_time = row.ended_at or row.started_at
            if ref_time.astimezone(UTC) < cutoff:
                _mark(row.execution_id)

    if policy.max_executions is not None:
        surviving = [row for row, _ in eligible if row.execution_id not in to_delete_ids]
        excess = len(surviving) - policy.max_executions
        if excess > 0:
            for row in reversed(surviving[-excess:]):
                _mark(row.execution_id)

    if policy.max_total_bytes is not None:
        remaining_bytes = total_dir_bytes - sum(size_by_id[eid] for eid in to_delete_ids)
        for row, size in reversed(eligible):
            if remaining_bytes <= policy.max_total_bytes:
                break
            if row.execution_id not in to_delete_ids:
                _mark(row.execution_id)
                remaining_bytes -= size

    reclaimed_bytes = sum(size_by_id[eid] for eid in to_delete_order)
    if policy.dry_run:
        return RetentionReport(
            dry_run=True,
            candidate_execution_ids=tuple(to_delete_order),
            deleted_execution_ids=(),
            protected_execution_ids=tuple(protected_ids),
            reclaimed_bytes=reclaimed_bytes,
            compacted=False,
        )

    store.delete_executions(to_delete_order)
    for eid in to_delete_order:
        exec_dir = resolve_execution_dir(data_dir, eid)
        if exec_dir.exists():
            shutil.rmtree(exec_dir)

    compacted = False
    if vacuum:
        store.compact()
        compacted = True

    return RetentionReport(
        dry_run=False,
        candidate_execution_ids=tuple(to_delete_order),
        deleted_execution_ids=tuple(to_delete_order),
        protected_execution_ids=tuple(protected_ids),
        reclaimed_bytes=reclaimed_bytes,
        compacted=compacted,
    )


def compact_database(store: SQLiteMetadataStore) -> None:
    """Explicitly checkpoint WAL and ``VACUUM`` the SQLite index database."""
    store.compact()


__all__ = [
    "RetentionPolicy",
    "RetentionReport",
    "apply_retention",
    "compact_database",
]
