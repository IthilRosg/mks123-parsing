from pathlib import Path

import yaml


def test_github_ci_runs_locked_quality_and_repository_boundary_checks() -> None:
    project = Path(__file__).parents[1]
    workflow = project / ".github/workflows/ci.yml"
    assert workflow.is_file()
    payload = yaml.safe_load(workflow.read_text(encoding="utf-8"))

    assert payload["permissions"] == {"contents": "read"}
    job = payload["jobs"]["quality"]
    assert job["strategy"]["matrix"]["python-version"] == ["3.11"]
    assert job["env"]["PYTHONPATH"] == "."
    steps = job["steps"]
    checkout = steps[0]
    setup_uv = steps[1]
    assert checkout["uses"] == "actions/checkout@11d5960a326750d5838078e36cf38b85af677262"
    assert checkout["with"]["persist-credentials"] is False
    assert setup_uv["uses"] == "astral-sh/setup-uv@d0cc045d04ccac9d8b7881df0226f9e82c39688e"
    commands = "\n".join(step.get("run", "") for step in steps)
    assert "uv sync --frozen" in commands
    assert "uv run python scripts/check_repository_boundary.py" in commands
    assert "uv run python -m pytest -q" in commands
    assert "uv run ruff check ." in commands
    assert "uv run python -m compileall -q" in commands
