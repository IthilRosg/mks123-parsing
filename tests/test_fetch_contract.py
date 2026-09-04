from pathlib import Path

REPO_ROOT = Path(__file__).parents[1]
FETCH_LAUNCHER = REPO_ROOT / "scripts" / "fetch_electrozone_current.py"
FETCH_WRAPPER = REPO_ROOT / "scripts" / "run_fetch_electrozone_current.ps1"


def test_fetch_launcher_has_no_production_database_connector() -> None:
    source = FETCH_LAUNCHER.read_text(encoding="utf-8")

    assert "mysqli" not in source
    assert "oc_suppler_cron" not in source
    assert "DB_HOSTNAME" not in source
    assert "DB_USERNAME" not in source
    assert "DB_PASSWORD" not in source
    assert "DB_DATABASE" not in source
    assert "legacy_server_credentialed_feed" not in source


def test_fetch_launcher_uses_supplier_https_without_ssh_trampoline() -> None:
    source = FETCH_LAUNCHER.read_text(encoding="utf-8")

    assert "urllib.request" in source
    assert "https://electrozon.ru/files/market_whs.yml" in source
    assert "paramiko" not in source
    assert "FIN_SSH_" not in source
    assert "exec_command" not in source
    assert "php -r" not in source


def test_fetch_wrapper_provisions_feed_credentials_from_dpapi_store() -> None:
    source = FETCH_WRAPPER.read_text(encoding="utf-8")

    assert "FIN_ELECTROZONE_FEED_CREDENTIAL_PATH" in source
    assert "Import-Clixml" in source
    assert "FIN_ELECTROZONE_FEED_USER" in source
    assert "FIN_ELECTROZONE_FEED_PASS" in source
    assert "FIN_SSH_" not in source
    assert "mks123-zenit" not in source