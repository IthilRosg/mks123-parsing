from __future__ import annotations

import errno
import os
import sys
from pathlib import Path

import pytest

from mks123_pipeline import netlab_media_finalize as final

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux-only inode and syscall integration")


def _skip_unavailable(exc: OSError, capability: str) -> None:
    if exc.errno in {errno.EPERM, errno.EACCES, errno.EOPNOTSUPP, errno.ENOTTY, errno.EINVAL, errno.ENOSYS}:
        pytest.skip(f"{capability} genuinely unavailable on this privilege/filesystem: errno={exc.errno}")
    raise exc


def test_real_otmpfile_linkat_empty_path_and_immutable_flag(tmp_path: Path) -> None:
    bucket_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    anonymous = -1
    published = -1
    try:
        try:
            anonymous = os.open(".", os.O_RDWR | os.O_TMPFILE, 0o600, dir_fd=bucket_fd)
            os.write(anonymous, b"object")
            os.fsync(anonymous)
            final._linkat_empty(anonymous, bucket_fd, "object.webp")
            published = os.open("object.webp", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=bucket_fd)
            final._set_flag(published, final.FS_IMMUTABLE_FL)
            assert final._flags(published) & final.FS_IMMUTABLE_FL
            assert os.read(published, 6) == b"object"
        except OSError as exc:
            _skip_unavailable(exc, "O_TMPFILE/linkat(AT_EMPTY_PATH)/immutable")
        finally:
            if published >= 0:
                try:
                    final._flags(published, final._flags(published) & ~final.FS_IMMUTABLE_FL)
                except OSError:
                    pass
    finally:
        if published >= 0:
            os.close(published)
        if anonymous >= 0:
            os.close(anonymous)
        os.close(bucket_fd)


def test_real_renameat2_noreplace_and_directory_fsync(tmp_path: Path) -> None:
    source = tmp_path / "private"
    destination = tmp_path / "run"
    source.mkdir()
    try:
        final._rename_noreplace(source, destination, test_only_allow_unenforced=False)
    except OSError as exc:
        _skip_unavailable(exc, "renameat2(RENAME_NOREPLACE)")
    parent_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent_fd)
    except OSError as exc:
        _skip_unavailable(exc, "directory fsync")
    finally:
        os.close(parent_fd)
    assert destination.is_dir() and not source.exists()
    replacement = tmp_path / "replacement"
    replacement.mkdir()
    with pytest.raises(FileExistsError):
        final._rename_noreplace(replacement, destination, test_only_allow_unenforced=False)


def test_kernel_lock_excludes_second_nonblocking_holder(tmp_path: Path) -> None:
    try:
        import fcntl
    except ImportError:
        pytest.skip("fcntl genuinely unavailable")
    lock_path = tmp_path / "lock"
    first = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    second = os.open(lock_path, os.O_RDWR)
    try:
        fcntl.flock(first, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(BlockingIOError):
            fcntl.flock(second, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(second)
        os.close(first)
