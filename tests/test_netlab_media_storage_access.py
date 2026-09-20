import os
import stat
from pathlib import Path

import pytest

from mks123_pipeline.netlab_media_finalize import init_storage


@pytest.mark.skipif(os.name == 'nt', reason='POSIX ownership contract')
def test_storage_metadata_is_root_owned_and_writer_readable(tmp_path: Path) -> None:
    root = tmp_path / 'media'
    init_storage(root, writer_uid=1000, writer_gid=1000, test_only_allow_unenforced=True)
    metadata = root / 'storage.json'
    info = metadata.stat()
    assert info.st_uid == 0
    assert info.st_gid == 1000
    assert stat.S_IMODE(info.st_mode) == 0o440
    root_info = root.stat()
    assert root_info.st_uid == 0
    assert root_info.st_gid == 1000
    assert stat.S_IMODE(root_info.st_mode) == 0o750
    for name in ('cas', 'runs'):
        directory = root / name
        directory_info = directory.stat()
        assert directory_info.st_uid == 0
        assert directory_info.st_gid == 1000
        assert stat.S_IMODE(directory_info.st_mode) == 0o750


def test_storage_initialization_is_idempotent_after_append_flags(tmp_path: Path) -> None:
    root = tmp_path / 'media'
    init_storage(root, writer_uid=1000, writer_gid=1000, test_only_allow_unenforced=True)
    init_storage(root, writer_uid=1000, writer_gid=1000, test_only_allow_unenforced=True)
