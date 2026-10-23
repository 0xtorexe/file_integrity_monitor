"""Shared operations used by both the CLI and the desktop GUI.

Keeping this logic in one place guarantees that both interfaces resolve paths,
apply excludes, handle unreadable files, and report changes in the same way.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .baseline import (
    DEFAULT_BASELINE_NAME,
    Baseline,
    load_baseline,
    save_baseline,
)
from .checker import ComparisonResult, compare
from .errors import BaselineExistsError, FimError
from .scanner import ScanResult, scan_directory


@dataclass
class CheckOutcome:
    """Everything produced by an integrity check."""

    root: Path
    baseline_path: Path
    baseline: Baseline
    scan: ScanResult
    comparison: ComparisonResult


def resolve_directory(directory: str | Path) -> Path:
    """Return an absolute directory path or raise a user-facing error."""
    root = Path(directory).expanduser().resolve()
    if not root.exists():
        raise FimError(f"directory does not exist: {root}")
    if not root.is_dir():
        raise FimError(f"not a directory: {root}")
    return root


def baseline_path_for(root: Path, baseline: str | Path | None = None) -> Path:
    """Return the baseline path for a monitored ``root``."""
    if baseline:
        return Path(baseline).expanduser().resolve()
    return root / DEFAULT_BASELINE_NAME


def create_baseline(
    directory: str | Path,
    *,
    baseline: str | Path | None = None,
    excludes: Iterable[str] = (),
    force: bool = False,
) -> tuple[Baseline, ScanResult]:
    """Scan ``directory`` and store a new baseline.

    Raises :class:`BaselineExistsError` when a baseline is already present and
    ``force`` is false.
    """
    root = resolve_directory(directory)
    path = baseline_path_for(root, baseline)

    if path.exists():
        if path.is_dir():
            raise FimError(f"baseline path is a directory: {path}")
        if not force:
            raise BaselineExistsError(path)

    scan = scan_directory(root, excludes=excludes, skip_paths=[path])
    return save_baseline(path, scan), scan


def check_integrity(
    directory: str | Path,
    *,
    baseline: str | Path | None = None,
    excludes: Iterable[str] = (),
) -> CheckOutcome:
    """Compare the current state of ``directory`` with its baseline."""
    root = resolve_directory(directory)
    path = baseline_path_for(root, baseline)
    stored = load_baseline(path)
    scan = scan_directory(root, excludes=excludes, skip_paths=[path])

    if str(root) != stored.root:
        scan.warnings.insert(
            0,
            f"baseline was created for a different directory: {stored.root}",
        )

    # Paths that could not be read are excluded from both sides so that an
    # inaccessible file is not reported as deleted.
    comparison = compare(
        {
            relative: record
            for relative, record in stored.files.items()
            if not scan.is_unreadable(relative)
        },
        {
            relative: record
            for relative, record in scan.files.items()
            if not scan.is_unreadable(relative)
        },
    )

    return CheckOutcome(
        root=root,
        baseline_path=path,
        baseline=stored,
        scan=scan,
        comparison=comparison,
    )
