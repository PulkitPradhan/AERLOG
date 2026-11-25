"""Defensive acceptance tests for SQLite storage on local Linux."""

from __future__ import annotations

import errno
import os
import stat
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import pytest

from aerlog.config import default_data_dir
from aerlog.storage.database import SQLiteMetadataStore
from aerlog.storage.exceptions import StorageWriteError
from aerlog.storage.migrations import LATEST_DB_SCHEMA_VERSION


def _assert_refused_before_sqlite(store: SQLiteMetadataStore) -> None:
    """Block mutation so checking rejection is safe against any implementation."""
    original_open = os.open

    def guarded_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if flags & (os.O_CREAT | os.O_TRUNC):
            raise AssertionError("Unsafe SQLite path reached file creation")
        return original_open(path, flags, mode, dir_fd=dir_fd)

    def guarded_mkdir(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> None:
        try:
            os.stat(path, dir_fd=dir_fd, follow_symlinks=False)
        except FileNotFoundError:
            raise AssertionError("Unsafe SQLite path reached directory creation") from None
        raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), path)

    with (
        patch("sqlite3.connect", side_effect=AssertionError("Unsafe path reached SQLite")),
        patch("os.mkdir", side_effect=guarded_mkdir),
        patch("os.open", side_effect=guarded_open),
        patch("os.chmod", side_effect=AssertionError("Unsafe path reached pathname chmod")),
        patch("os.fchmod", side_effect=AssertionError("Unsafe path reached descriptor chmod")),
        pytest.raises(StorageWriteError),
    ):
        store.initialize()
    assert not store.is_open


def test_first_run_and_reopen_use_private_sqlite_files(tmp_path: Path) -> None:
    data_dir = default_data_dir({"XDG_DATA_HOME": str(tmp_path / "share")})
    for _ in range(2):
        store = SQLiteMetadataStore(data_dir)
        try:
            assert store.initialize() == LATEST_DB_SCHEMA_VERSION
            assert stat.S_IMODE(data_dir.stat().st_mode) == 0o700
            for suffix in ("", "-wal", "-shm"):
                metadata = Path(f"{store.db_path}{suffix}").lstat()
                assert stat.S_ISREG(metadata.st_mode)
                assert stat.S_IMODE(metadata.st_mode) == 0o600
                assert metadata.st_uid == os.geteuid()
                assert metadata.st_nlink == 1
        finally:
            store.close()


def test_accepts_private_store_below_root_owned_sticky_ancestor() -> None:
    temp_root = Path("/tmp")
    metadata = temp_root.lstat()
    if metadata.st_uid != 0 or not metadata.st_mode & stat.S_ISVTX:
        pytest.skip("/tmp is not a root-owned sticky directory")
    with TemporaryDirectory(dir=temp_root) as temporary:
        store = SQLiteMetadataStore(Path(temporary) / "aerlog")
        try:
            assert store.initialize() == LATEST_DB_SCHEMA_VERSION
        finally:
            store.close()


def test_accepts_direct_database_path_below_private_data_dir(tmp_path: Path) -> None:
    data_dir = tmp_path / "aerlog"
    parent = data_dir / "index"
    db_path = parent / "custom.db"
    store = SQLiteMetadataStore(data_dir, db_path=db_path)
    try:
        assert store.initialize() == LATEST_DB_SCHEMA_VERSION
        assert stat.S_IMODE(data_dir.stat().st_mode) == 0o700
        assert stat.S_IMODE(parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(db_path.stat().st_mode) == 0o600
    finally:
        store.close()


@pytest.mark.parametrize("mode", [0o755, 0o770])
def test_refuses_nonprivate_existing_data_dir(tmp_path: Path, mode: int) -> None:
    data_dir = tmp_path / "aerlog"
    data_dir.mkdir()
    data_dir.chmod(mode)
    store = SQLiteMetadataStore(data_dir)

    _assert_refused_before_sqlite(store)

    assert stat.S_IMODE(data_dir.stat().st_mode) == mode
    assert not store.db_path.exists()


@pytest.mark.parametrize("mode", [0o775, 0o777])
def test_refuses_writable_ancestor_before_creating_store(tmp_path: Path, mode: int) -> None:
    ancestor = tmp_path / "shared"
    ancestor.mkdir()
    ancestor.chmod(mode)
    _assert_refused_before_sqlite(SQLiteMetadataStore(ancestor / "aerlog"))

    assert list(ancestor.iterdir()) == []


@pytest.mark.parametrize("location", ["data dir", "ancestor"])
def test_refuses_symlink_directory_components(tmp_path: Path, location: str) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(private, target_is_directory=True)
    data_dir = alias if location == "data dir" else alias / "aerlog"

    _assert_refused_before_sqlite(SQLiteMetadataStore(data_dir))

    assert list(private.iterdir()) == []


@pytest.mark.parametrize("relative", [False, True])
def test_direct_database_path_cannot_select_files_outside_store(
    tmp_path: Path, relative: bool
) -> None:
    data_dir = tmp_path / "aerlog"
    data_dir.mkdir(mode=0o700)
    outside = tmp_path / "ordinary.txt"
    outside.write_bytes(b"ordinary file")
    outside.chmod(0o640)
    db_path = data_dir / ".." / outside.name if relative else outside

    _assert_refused_before_sqlite(SQLiteMetadataStore(data_dir, db_path=db_path))

    assert list(data_dir.iterdir()) == []
    assert stat.S_IMODE(outside.stat().st_mode) == 0o640
    assert outside.read_bytes() == b"ordinary file"


def test_refuses_nonprivate_parent_of_direct_database_path(tmp_path: Path) -> None:
    parent = tmp_path / "index"
    parent.mkdir(mode=0o755)
    store = SQLiteMetadataStore(tmp_path, db_path=parent / "custom.db")

    _assert_refused_before_sqlite(store)

    assert not store.db_path.exists()


@pytest.mark.parametrize(
    "suffix", ["", "-wal", "-shm", "-journal"], ids=["db", "wal", "shm", "journal"]
)
@pytest.mark.parametrize(
    "kind", ["directory", "fifo", "group-readable", "symlink", "dangling-symlink", "hardlink"]
)
def test_refuses_unsafe_database_and_sidecar_metadata(
    tmp_path: Path, suffix: str, kind: str
) -> None:
    data_dir = tmp_path / "aerlog"
    data_dir.mkdir(mode=0o700)
    store = SQLiteMetadataStore(data_dir)
    candidate = Path(f"{store.db_path}{suffix}")
    outside = tmp_path / "ordinary.txt"
    outside.write_bytes(b"ordinary file")
    outside.chmod(0o600)
    if kind == "directory":
        candidate.mkdir(mode=0o700)
    elif kind == "fifo":
        os.mkfifo(candidate, mode=0o600)
    elif kind == "group-readable":
        candidate.touch()
        candidate.chmod(0o640)
    elif kind == "symlink":
        candidate.symlink_to(outside)
    elif kind == "dangling-symlink":
        candidate.symlink_to(tmp_path / "missing")
    else:
        candidate.hardlink_to(outside)

    before = candidate.lstat()
    _assert_refused_before_sqlite(store)

    after = candidate.lstat()
    assert (after.st_ino, after.st_mode, after.st_nlink) == (
        before.st_ino,
        before.st_mode,
        before.st_nlink,
    )
    assert outside.read_bytes() == b"ordinary file"
    assert stat.S_IMODE(outside.stat().st_mode) == 0o600
    if suffix:
        assert not store.db_path.exists()
