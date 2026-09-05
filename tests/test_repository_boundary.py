import pytest

from scripts.check_repository_boundary import check_paths, scan_text


def test_repository_boundary_blocks_generated_and_secret_artifact_paths() -> None:
    findings = check_paths(
        [
            ".ops-tmp/run/report.json",
            "raw/netlab.zip",
            "runs/live/pilot.duckdb",
            ".env",
            "safe/module.py",
        ]
    )

    assert set(findings) == {
        ".ops-tmp/run/report.json",
        "raw/netlab.zip",
        "runs/live/pilot.duckdb",
        ".env",
    }


def test_repository_boundary_allows_safe_credential_provisioning_helper() -> None:
    assert check_paths(["scripts/provision_supplier_credential.ps1"]) == []


def test_repository_boundary_flags_hardcoded_secret_assignment() -> None:
    secret_assignment = "PASS" + 'WORD = "' + "fixture-value-not-real" + '"\n'
    findings = scan_text("config.py", secret_assignment)

    assert findings == ["config.py:1:hardcoded_secret_assignment"]


def test_repository_boundary_allows_documented_secret_field_names() -> None:
    assert scan_text("README.md", "Credentials and passwords are never stored.\n") == []


@pytest.mark.parametrize(
    "secret_assignment",
    [
        "pass" + "word: fixture-value-not-real",
        '{"api_' + 'key":"fixture-value-not-real"}',
    ],
)
def test_repository_boundary_flags_yaml_and_json_literal_secrets(secret_assignment: str) -> None:
    assert scan_text("unsafe-config.txt", secret_assignment) == [
        "unsafe-config.txt:1:hardcoded_secret_assignment"
    ]
