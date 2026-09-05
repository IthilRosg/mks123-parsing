from __future__ import annotations

import re
import subprocess
from pathlib import Path, PurePosixPath

_FORBIDDEN_COMPONENTS = {
    ".ops-tmp",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "raw",
    "reports",
    "runs",
    "snapshots",
    "verification",
}
_FORBIDDEN_NAMES = {
    ".env",
    "credential.xml",
    "cookies.txt",
    "id_rsa",
    "id_ed25519",
}
_FORBIDDEN_SUFFIXES = {
    ".db",
    ".duckdb",
    ".key",
    ".p12",
    ".pem",
    ".pfx",
    ".sqlite",
    ".sqlite3",
}
_SECRET_ASSIGNMENT = re.compile(
    r"^\s*[\{\[]?\s*(?:export\s+|\$)?['\"]?(?:api[_-]?key|access[_-]?token|auth[_-]?token|"
    r"client[_-]?secret|password|passwd|private[_-]?key)['\"]?\s*(?::|=)\s*(?P<value>.+?)\s*$",
    re.IGNORECASE,
)


def _is_literal_secret(value: str) -> bool:
    candidate = value.strip().rstrip(",}").strip()
    if len(candidate) >= 2 and candidate[0] == candidate[-1] and candidate[0] in {'"', "'"}:
        candidate = candidate[1:-1].strip()
    lowered = candidate.casefold()
    if len(candidate) < 6 or lowered in {"null", "none", "redacted", "example", "changeme"}:
        return False
    return not lowered.startswith(("$", "%", "${", "{{", "<", "env:", "environment:", "read-host", "getpass", "os.environ"))


def check_paths(paths: list[str]) -> list[str]:
    findings: list[str] = []
    for raw_path in paths:
        normalized = raw_path.replace("\\", "/")
        path = PurePosixPath(normalized)
        components = {part.casefold() for part in path.parts}
        name = path.name.casefold()
        suffix = path.suffix.casefold()
        if (
            components & _FORBIDDEN_COMPONENTS
            or name in _FORBIDDEN_NAMES
            or name.startswith(".env.")
            or suffix in _FORBIDDEN_SUFFIXES
        ):
            findings.append(normalized)
    return sorted(set(findings))


def scan_text(path: str, text: str) -> list[str]:
    findings: list[str] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = _SECRET_ASSIGNMENT.search(line)
        if match and _is_literal_secret(match.group("value")):
            findings.append(f"{path}:{line_number}:hardcoded_secret_assignment")
    return findings


def _tracked_paths(root: Path) -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=root,
        capture_output=True,
        check=True,
    )
    return [item.decode("utf-8") for item in result.stdout.split(b"\0") if item]


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    tracked = _tracked_paths(root)
    findings = [f"forbidden_tracked_path:{path}" for path in check_paths(tracked)]
    for relative in tracked:
        path = root / relative
        try:
            if path.stat().st_size > 2 * 1024 * 1024:
                findings.append(f"tracked_file_too_large_for_source_boundary:{relative}")
                continue
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            findings.append(f"tracked_binary_file:{relative}")
            continue
        findings.extend(scan_text(relative, text))
    if findings:
        for finding in sorted(findings):
            print(finding)
        return 1
    print(f"REPOSITORY_BOUNDARY_PASS tracked_files={len(tracked)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
