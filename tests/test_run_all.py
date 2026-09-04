import hashlib
import json
import stat
from pathlib import Path

from run_all import _write_approval_template


def test_approval_template_binds_seal_and_blocks_incomplete_feed(tmp_path: Path) -> None:
    run = tmp_path / "electrozone-run"
    run.mkdir()
    seal = run / "seal.json"
    seal.write_text("seal", encoding="utf-8")
    (run / "run-manifest.json").write_text(
        json.dumps({"run_id": "electrozone-canonical", "supplier": "electrozone"}),
        encoding="utf-8",
    )
    (run / "reports").mkdir()
    (run / "reports/summary.json").write_text(
        json.dumps({
            "mode": "read_only",
            "production_writes": 0,
            "feed_completeness": {"status": "blocked_incomplete"},
        }),
        encoding="utf-8",
    )

    artifact = _write_approval_template(run, tmp_path / "approval")

    payload = json.loads(artifact.read_text(encoding="utf-8"))
    assert payload["status"] == "pending_approval"
    assert payload["eligible"] is False
    assert payload["seal_sha256"] == hashlib.sha256(b"seal").hexdigest()
    assert payload["production_writes"] == 0
    assert not (artifact.stat().st_mode & stat.S_IWRITE)
