from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

from scripts import run_netlab_shadow as shadow


def _write_inputs(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    catalog = tmp_path / "catalog.csv"
    catalog.write_text("catalog", encoding="utf-8")
    config = tmp_path / "netlab.yaml"
    config.write_text("config", encoding="utf-8")
    raw_root = tmp_path / "raw"
    raw_root.mkdir()
    runs_root = tmp_path / "runs"
    return catalog, config, raw_root, runs_root




def test_accepted_snapshot_returns_bound_evidence(tmp_path: Path) -> None:
    raw_root = tmp_path / "raw"
    raw_root.mkdir()
    source = raw_root / "feed.zip"
    source.write_bytes(b"feed")
    metadata = raw_root / "feed.metadata.json"
    metadata.write_text(json.dumps({"fetched_at_utc": "2026-09-05T00:00:00Z"}), encoding="utf-8")
    digest = hashlib.sha256(b"feed").hexdigest()

    accepted_source, accepted_metadata, source_hash, fetched_at = shadow._accepted_snapshot(
        raw_root=raw_root,
        fetched={"production_writes": 0, "local_file": source.name, "sha256": digest, "fetched_at_utc": "2026-09-05T00:00:00Z"},
        label="price",
    )

    assert accepted_source.data == b"feed"
    assert accepted_source.canonical_path.endswith("feed.zip")
    assert accepted_metadata.data.startswith(b"{")
    assert source_hash == digest
    assert fetched_at.endswith("Z")


def test_shadow_cycle_skips_repricing_only_after_existing_run_verifies(
    tmp_path: Path,
    monkeypatch,
) -> None:
    catalog, config, raw_root, runs_root = _write_inputs(tmp_path)
    source_bytes = b"zip"
    source_hash = hashlib.sha256(source_bytes).hexdigest()
    source = raw_root / "netlab-live.zip"
    source.write_bytes(source_bytes)
    source.with_suffix(".metadata.json").write_text("{}", encoding="utf-8")
    policy_hash = "d" * 64
    run_name = shadow._run_name(
        source_hash,
        shadow._sha256(catalog),
        shadow._sha256(config),
        policy_hash,
        shadow._code_sha256(),
        properties_hash=source_hash,
    )
    run_dir = runs_root / run_name
    run_dir.mkdir(parents=True)
    calls: list[list[str]] = []

    def fake_run(command: list[str]) -> dict:
        calls.append(command)
        if "fetch_netlab_current.py" in command[1]:
            kind = command[command.index("--kind") + 1]
            return {
                "deduplicated": True,
                "kind": kind,
                "local_file": source.name,
                "sha256": source_hash,
                "feed_catalog_date": "2026-09-04 12:04",
                "fetched_at_utc": "2026-09-04T10:02:40Z",
                "production_writes": 0,
            }
        return {"status": "PASS", "checks_passed": 41, "checks_total": 41}

    monkeypatch.setattr(shadow, "_run_json", fake_run)
    monkeypatch.setattr(shadow, "_policy_hash", lambda *args: policy_hash)
    monkeypatch.setattr(shadow, "_assert_run_identity", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        shadow,
        "load_pilot_config",
        lambda *_: SimpleNamespace(supplier=SimpleNamespace(source=SimpleNamespace(max_response_bytes=256 * 1024 * 1024))),
    )

    result = shadow.run_cycle(
        catalog=catalog,
        config=config,
        raw_root=raw_root,
        runs_root=runs_root,
    )

    assert result["status"] == "NO_CHANGE"
    assert result["run"] == str(run_dir)
    assert result["production_writes"] == 0
    assert len(calls) == 3
    assert "verify_run.py" in calls[2][1]


def test_shadow_cycle_runs_full_pipeline_for_new_source(
    tmp_path: Path,
    monkeypatch,
) -> None:
    catalog, config, raw_root, runs_root = _write_inputs(tmp_path)
    source_bytes = b"zip"
    source_hash = hashlib.sha256(source_bytes).hexdigest()
    source = raw_root / "netlab-live.zip"
    source.write_bytes(source_bytes)
    source.with_suffix(".metadata.json").write_text("{}", encoding="utf-8")
    policy_hash = "d" * 64
    calls: list[list[str]] = []

    def fake_run(command: list[str]) -> dict:
        calls.append(command)
        if "fetch_netlab_current.py" in command[1]:
            kind = command[command.index("--kind") + 1]
            return {
                "deduplicated": False,
                "kind": kind,
                "local_file": source.name,
                "sha256": source_hash,
                "feed_catalog_date": "2026-09-04 12:04",
                "fetched_at_utc": "2026-09-04T10:02:40Z",
                "production_writes": 0,
            }
        if "run_pilot.py" in command[1]:
            output = Path(command[command.index("--output") + 1])
            output.mkdir(parents=True)
            return {"production_writes": 0, "proposals": {"ready_for_review": 3}}
        return {"status": "PASS", "checks_passed": 41, "checks_total": 41}

    monkeypatch.setattr(shadow, "_run_json", fake_run)
    monkeypatch.setattr(shadow, "_policy_hash", lambda *args: policy_hash)
    monkeypatch.setattr(shadow, "_assert_run_identity", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        shadow,
        "load_pilot_config",
        lambda *_: SimpleNamespace(supplier=SimpleNamespace(source=SimpleNamespace(max_response_bytes=256 * 1024 * 1024))),
    )

    result = shadow.run_cycle(
        catalog=catalog,
        config=config,
        raw_root=raw_root,
        runs_root=runs_root,
    )

    expected = runs_root / shadow._run_name(
        source_hash,
        hashlib.sha256(catalog.read_bytes()).hexdigest(),
        hashlib.sha256(config.read_bytes()).hexdigest(),
        policy_hash,
        shadow._code_sha256(),
        properties_hash=source_hash,
    )
    assert result["status"] == "UPDATED_SHADOW"
    assert result["run"] == str(expected)
    assert result["production_writes"] == 0
    assert len(calls) == 4
    assert "run_pilot.py" in calls[2][1]
    assert "verify_run.py" in calls[3][1]


def test_run_name_changes_when_executable_code_changes(tmp_path: Path) -> None:
    project = tmp_path / "project"
    package = project / "mks123_pipeline"
    scripts = project / "scripts"
    package.mkdir(parents=True)
    scripts.mkdir()
    pricing = package / "pricing.py"
    pricing.write_text("POLICY = 1\n", encoding="utf-8")
    (project / "run_pilot.py").write_text("pass\n", encoding="utf-8")
    (project / "verify_run.py").write_text("pass\n", encoding="utf-8")
    (scripts / "fetch_netlab_current.py").write_text("pass\n", encoding="utf-8")

    first_code_hash = shadow._code_sha256(project)
    first = shadow._run_name("a" * 64, "b" * 64, "c" * 64, "d" * 64, first_code_hash)
    pricing.write_text("POLICY = 2\n", encoding="utf-8")
    second_code_hash = shadow._code_sha256(project)
    second = shadow._run_name("a" * 64, "b" * 64, "c" * 64, "d" * 64, second_code_hash)

    assert first_code_hash != second_code_hash
    assert first != second


def test_run_name_changes_when_lockfile_changes(tmp_path: Path) -> None:
    project = tmp_path / "project"
    (project / "mks123_pipeline").mkdir(parents=True)
    (project / "scripts").mkdir()
    (project / "mks123_pipeline/pricing.py").write_text("POLICY = 1\n", encoding="utf-8")
    (project / "run_pilot.py").write_text("pass\n", encoding="utf-8")
    (project / "verify_run.py").write_text("pass\n", encoding="utf-8")
    (project / "scripts/fetch_netlab_current.py").write_text("pass\n", encoding="utf-8")
    (project / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")
    lockfile = project / "uv.lock"
    lockfile.write_text("version = 1\n", encoding="utf-8")

    first = shadow._code_sha256(project)
    lockfile.write_text("version = 2\n", encoding="utf-8")
    second = shadow._code_sha256(project)

    assert first != second
