from __future__ import annotations

import ast
import hashlib
import inspect

from mks123_pipeline import netlab_media, netlab_media_cli, netlab_media_finalize
from mks123_pipeline.netlab_media import stage_media_plan
from mks123_pipeline.netlab_media_finalize import finalize_media_stage


def test_stage_and_finalize_have_disjoint_network_and_privilege_boundaries() -> None:
    assert "fetcher" in inspect.signature(stage_media_plan).parameters
    parameters = inspect.signature(finalize_media_stage).parameters
    assert "fetcher" not in parameters
    assert "opener" not in parameters
    assert {"stage_id", "media_run_id", "expected_stage_seal_sha256"} <= set(parameters)


def test_combined_entrypoints_are_absent() -> None:
    assert not hasattr(netlab_media, "ingest_media_plan")
    choices = netlab_media_cli._parser()._subparsers._group_actions[0].choices
    assert set(choices) == {"init-storage", "plan", "stage", "finalize", "verify"}
    assert "ingest" not in choices


def test_finalize_source_has_no_network_injection_or_fetch() -> None:
    source = inspect.getsource(netlab_media_finalize)
    tree = ast.parse(source)
    forbidden = {"urllib", "http", "socket", "requests", "aiohttp", "fetcher", "opener", "urlopen"}
    names = {node.id.lower() for node in ast.walk(tree) if isinstance(node, ast.Name)}
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".")[0].lower() for alias in node.names)
            imports.update(alias.asname.lower() for alias in node.names if alias.asname)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0].lower())
            imports.update(alias.name.split(".")[0].lower() for alias in node.names)
            imports.update(alias.asname.lower() for alias in node.names if alias.asname)
    module_globals = {name.lower() for name in vars(netlab_media_finalize)}
    assert not forbidden & (names | imports | module_globals)
    assert not any(hasattr(netlab_media, name) for name in ("finalize_media_stage", "verify_media_run", "init_storage"))
    assert hashlib.sha256(source.encode()).hexdigest()


def test_linux_publication_uses_required_create_only_primitives() -> None:
    cas_source = inspect.getsource(netlab_media_finalize._install_cas)
    link_source = inspect.getsource(netlab_media_finalize._linkat_empty)
    run_source = inspect.getsource(netlab_media_finalize._rename_noreplace)
    finalize_source = inspect.getsource(finalize_media_stage)

    assert "O_TMPFILE" in cas_source
    assert "AT_EMPTY_PATH" in link_source
    assert "os.link" not in cas_source
    assert "RENAME_NOREPLACE" in run_source
    assert "os.fsync" in cas_source
    assert "os.fsync" in finalize_source
