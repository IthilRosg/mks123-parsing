"""Trusted sealed run-manifest loading for candidate provenance."""

from __future__ import annotations

import json
import os
import re
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .integrity import IntegrityDeadlineExceeded, load_sealed_run


def _default_trusted_run_root(platform_name: str | None = None) -> Path:
    """Return the fixed durable trust root for the execution platform."""
    platform = os.name if platform_name is None else platform_name
    if platform == "posix":
        return Path("/var/lib/mks123/trusted-runs")
    return Path("D:/ServerBackups/mks123webserver")


DEFAULT_TRUSTED_RUN_ROOT = _default_trusted_run_root()


class TrustedRunError(ValueError):
    """Raised when a run manifest is not backed by a verified enclosing seal."""


def load_trusted_run_manifest(
    path: str | Path,
    *,
    expected_seal_sha256: str,
    deadline_check: Callable[[], None] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Load a run manifest backed by an externally anchored sealed run."""
    candidate = Path(path)
    if deadline_check is not None:
        deadline_check()
    if not isinstance(expected_seal_sha256, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected_seal_sha256):
        raise TrustedRunError("an external 64-hex run seal digest is required")
    root = DEFAULT_TRUSTED_RUN_ROOT
    if candidate.name != "run-manifest.json":
        raise TrustedRunError("trusted run manifest must be named run-manifest.json")
    try:
        raw_stat = os.lstat(candidate)
    except OSError as exc:
        raise TrustedRunError("trusted run manifest cannot be inspected") from exc
    if stat.S_ISLNK(raw_stat.st_mode) or not stat.S_ISREG(raw_stat.st_mode):
        raise TrustedRunError("trusted run manifest is not a regular file")
    try:
        manifest_path = candidate.resolve(strict=True)
        if deadline_check is not None:
            deadline_check()
        run_root = manifest_path.parent
        trusted_root_path = root.resolve(strict=True)
        if deadline_check is not None:
            deadline_check()
        if not run_root.is_relative_to(trusted_root_path):
            raise TrustedRunError("trusted run is outside the fixed durable trust root")
        sealed = load_sealed_run(
            run_root,
            read_content=os.name == "nt",
            deadline_check=deadline_check,
            content_filter=(None if os.name == "nt" else lambda relative: relative == "run-manifest.json"),
        )
        if sealed.seal_evidence.sha256.casefold() != expected_seal_sha256.casefold():
            raise TrustedRunError("trusted run seal digest is not the externally anchored digest")
    except IntegrityDeadlineExceeded:
        raise
    except TrustedRunError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise TrustedRunError("trusted run manifest is not backed by a verified seal") from exc

    evidence = sealed.files.get("run-manifest.json")
    if evidence is None or evidence.data == b"":
        raise TrustedRunError("verified run seal does not contain run-manifest.json")
    try:
        manifest = json.loads(evidence.data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TrustedRunError("sealed run manifest is invalid JSON") from exc
    if not isinstance(manifest, dict):
        raise TrustedRunError("sealed run manifest is not an object")
    identity = {
        "size": evidence.size if evidence.size is not None else len(evidence.data),
        "sha256": evidence.sha256,
    }
    seal_files: dict[str, dict[str, Any]] = {}
    for relative, evidence in sealed.files.items():
        if deadline_check is not None:
            deadline_check()
        seal_files[relative] = {
            "size": evidence.size if evidence.size is not None else len(evidence.data),
            "sha256": evidence.sha256,
            "canonical_path": evidence.canonical_path,
        }
    seal_metadata = {
        "run_root": str(run_root),
        "seal_version": sealed.seal.get("version"),
        "seal_sha256": sealed.seal_evidence.sha256,
        "files": seal_files,
    }
    return manifest, identity, seal_metadata
