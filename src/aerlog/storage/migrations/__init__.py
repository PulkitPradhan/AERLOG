"""Forward-only versioned SQLite schema migrations for AERLOG storage."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from aerlog.storage.exceptions import UnsupportedSchemaVersionError
from aerlog.storage.migrations import m0001_initial


@dataclass(frozen=True, slots=True)
class MigrationStep:
    """One forward-only SQLite migration step."""

    version: int
    name: str
    apply: Callable[[sqlite3.Connection], None]


MIGRATIONS: tuple[MigrationStep, ...] = (
    MigrationStep(
        version=m0001_initial.VERSION,
        name=m0001_initial.NAME,
        apply=m0001_initial.apply,
    ),
)

LATEST_DB_SCHEMA_VERSION: int = MIGRATIONS[-1].version


def _ensure_migrations_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at TEXT NOT NULL
        )
        """
    )


def _inspect_migration_state(
    conn: sqlite3.Connection,
) -> tuple[int, list[MigrationStep]]:
    """Read schema version state and compute pending migrations.

    Raises:
        UnsupportedSchemaVersionError: If the database records a schema version
            newer than ``LATEST_DB_SCHEMA_VERSION``.
    """
    row = conn.execute("PRAGMA user_version").fetchone()
    user_ver = int(row[0]) if row is not None else 0
    if user_ver > LATEST_DB_SCHEMA_VERSION:
        raise UnsupportedSchemaVersionError(
            f"SQLite database user_version {user_ver} is newer than supported "
            f"version {LATEST_DB_SCHEMA_VERSION}"
        )

    table_exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations'"
    ).fetchone()
    applied_versions: set[int] = set()
    if table_exists is not None:
        max_row = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
        max_applied = int(max_row[0]) if max_row is not None and max_row[0] is not None else 0
        if max_applied > LATEST_DB_SCHEMA_VERSION:
            raise UnsupportedSchemaVersionError(
                f"SQLite schema_migrations version {max_applied} is newer than supported "
                f"version {LATEST_DB_SCHEMA_VERSION}"
            )
        applied_versions = {
            int(r[0]) for r in conn.execute("SELECT version FROM schema_migrations").fetchall()
        }

    pending = [step for step in MIGRATIONS if step.version not in applied_versions]
    return user_ver, pending


def apply_migrations(conn: sqlite3.Connection) -> int:
    """Validate SQLite schema version and apply pending forward migrations atomically.

    Raises:
        UnsupportedSchemaVersionError: If the database on disk has a newer schema
            version than this binary supports.
    """
    user_ver, pending = _inspect_migration_state(conn)
    if not pending and user_ver == LATEST_DB_SCHEMA_VERSION:
        return LATEST_DB_SCHEMA_VERSION

    now_iso = datetime.now(UTC).isoformat()
    conn.execute("BEGIN IMMEDIATE")
    try:
        # Re-check inside BEGIN IMMEDIATE so concurrent processes initializing a fresh DB
        # do not re-apply migrations that a racing writer just committed.
        user_ver, pending = _inspect_migration_state(conn)
        if pending or user_ver != LATEST_DB_SCHEMA_VERSION:
            _ensure_migrations_table(conn)
            for step in pending:
                step.apply(conn)
                conn.execute(
                    "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
                    (step.version, step.name, now_iso),
                )
            conn.execute(f"PRAGMA user_version = {LATEST_DB_SCHEMA_VERSION}")
        conn.commit()
    except Exception:
        conn.rollback()
        raise

    return LATEST_DB_SCHEMA_VERSION


__all__ = [
    "LATEST_DB_SCHEMA_VERSION",
    "MIGRATIONS",
    "MigrationStep",
    "apply_migrations",
]
