"""Module 3: Baseline Manager.

Reads and writes the JSON baseline: the trusted snapshot of file paths and
SHA-256 hashes used by later integrity checks.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .errors import FimError
from .hasher import ALGORITHM
from .scanner import FileRecord, ScanResult

BASELINE_VERSION = 1
DEFAULT_BASELINE_NAME = ".fim_baseline.json"


@dataclass
class Baseline:
    """A loaded baseline file."""

    path: Path
    root: str
    created: str
    algorithm: str
    files: dict[str, FileRecord]


def save_baseline(path: str | Path, result: ScanResult) -> Baseline:
    """Write ``result`` to ``path`` atomically and return the new baseline."""
    baseline_path = Path(path).expanduser().resolve()
    created = datetime.now(timezone.utc).isoformat(timespec="seconds")
    files = {
        relative: {
            "sha256": record.sha256,
            "size": record.size,
            "mtime": record.mtime,
        }
        for relative, record in sorted(result.files.items())
    }
    data = {
        "version": BASELINE_VERSION,
        "algorithm": ALGORITHM,
        "created": created,
        "root": str(result.root),
        "file_count": len(files),
        "files": files,
    }

    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    # Write to a temporary file first so an interrupted save cannot leave a
    # half-written baseline behind.  mkstemp also creates the file with 0600
    # permissions, which keeps the baseline private to the current user.
    try:
        fd, temp_name = tempfile.mkstemp(
            prefix=f".{baseline_path.name}.", suffix=".tmp", dir=baseline_path.parent
        )
    except OSError as exc:
        raise FimError(f"cannot create baseline in {baseline_path.parent}: {exc}") from exc

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(temp_name, baseline_path)
    except OSError as exc:
        raise FimError(f"cannot write baseline {baseline_path}: {exc}") from exc
    finally:
        try:
            os.unlink(temp_name)
        except OSError:
            pass

    return Baseline(
        path=baseline_path,
        root=str(result.root),
        created=created,
        algorithm=ALGORITHM,
        files=dict(result.files),
    )


def load_baseline(path: str | Path) -> Baseline:
    """Load and validate a baseline file."""
    baseline_path = Path(path).expanduser().resolve()

    if not baseline_path.exists():
        raise FimError(
            f"baseline not found: {baseline_path}\n"
            "Run the 'baseline' command first to create one."
        )
    if not baseline_path.is_file():
        raise FimError(f"baseline is not a file: {baseline_path}")

    try:
        with open(baseline_path, encoding="utf-8") as handle:
            data = json.load(handle)
    except OSError as exc:
        raise FimError(f"cannot read baseline {baseline_path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise FimError(f"baseline is not valid JSON ({baseline_path}): {exc}") from exc

    if not isinstance(data, dict):
        raise FimError(f"baseline has an unexpected format: {baseline_path}")

    version = data.get("version")
    if version != BASELINE_VERSION:
        raise FimError(
            f"unsupported baseline version {version!r} in {baseline_path} "
            f"(this version of the tool expects {BASELINE_VERSION})"
        )

    algorithm = data.get("algorithm")
    if algorithm != ALGORITHM:
        raise FimError(
            f"baseline uses algorithm {algorithm!r}, but this tool only supports "
            f"{ALGORITHM!r}"
        )

    raw_files = data.get("files")
    if not isinstance(raw_files, dict):
        raise FimError(f"baseline is missing its 'files' table: {baseline_path}")

    files: dict[str, FileRecord] = {}
    for relative, entry in raw_files.items():
        if not isinstance(relative, str) or not isinstance(entry, dict):
            raise FimError(f"baseline contains an invalid entry for {relative!r}")
        try:
            files[relative] = FileRecord(
                path=relative,
                sha256=str(entry["sha256"]),
                size=int(entry["size"]),
                mtime=float(entry["mtime"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise FimError(f"baseline entry for {relative!r} is invalid") from exc

    return Baseline(
        path=baseline_path,
        root=str(data.get("root", "")),
        created=str(data.get("created", "unknown")),
        algorithm=algorithm,
        files=files,
    )
