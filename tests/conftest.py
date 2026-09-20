import os
from pathlib import Path

import pytest

from mks123_pipeline import integrity, trusted_run


@pytest.fixture(autouse=True)
def _test_trusted_run_root(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(trusted_run, "DEFAULT_TRUSTED_RUN_ROOT", tmp_path)


if os.name == "nt":
    integrity._WINDOWS_TEST_SEAL_BUILDER_ENABLED = True
