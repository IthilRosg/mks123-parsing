from pathlib import Path


def test_netlab_fetch_launcher_is_checkout_local_and_read_only() -> None:
    project = Path(__file__).parents[1]
    launcher = project / "scripts/run_fetch_netlab_current.ps1"

    text = launcher.read_text(encoding="utf-8")

    assert "fetch_netlab_current.py" in text
    assert "--kind price" in text
    assert "--kind properties" in text
    assert "production" not in text.casefold()
    assert "password" not in text.casefold()
    assert "token" not in text.casefold()
