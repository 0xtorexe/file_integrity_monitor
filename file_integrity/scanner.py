"""Module 1: Directory Scanner.

Walks a directory tree and turns every regular file into a :class:`FileRecord`
containing its relative path and SHA-256 hash.
"""

from __future__ import annotations

import fnmatch
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .errors import FimError
from .hasher import hash_file

#: The baseline file is never part of the monitored file set.
DEFAULT_EXCLUDES = (".fim_baseline.json",)


@dataclass(frozen=True)
class FileRecord:
    """Snapshot of one file: relative path, SHA-256, size and mtime."""

    path: str
    sha256: str
    size: int
    mtime: float


@dataclass
class ScanResult:
    """Result of scanning a directory."""

    root: Path
    files: dict[str, FileRecord] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    #: Relative file paths, and directory paths ending in "/", that could not
    #: be read.  They are excluded from comparisons to avoid false deletions.
    unreadable: list[str] = field(default_factory=list)

    def is_unreadable(self, relative: str) -> bool:
        """Return True if ``relative`` is covered by an unreadable path."""
        for entry in self.unreadable:
            if entry.endswith("/"):
                if relative.startswith(entry):
                    return True
            elif relative == entry:
                return True
        return False


def scan_directory(
    root: str | Path,
    excludes: Iterable[str] = (),
    skip_paths: Iterable[str | Path] = (),
) -> ScanResult:
    """Scan ``root`` and return a record for every readable regular file.

    ``excludes`` are glob patterns matched against both the path relative to
    ``root`` (``logs/*.txt``) and the bare file name (``*.log``).  ``skip_paths``
    are absolute paths that should not be hashed, such as the baseline file.
    Unreadable files are reported through ``ScanResult.warnings`` instead of
    aborting the whole scan.
    """
    root_path = Path(root).expanduser().resolve()
    if not root_path.exists():
        raise FimError(f"directory does not exist: {root_path}")
    if not root_path.is_dir():
        raise FimError(f"not a directory: {root_path}")

    patterns = tuple(DEFAULT_EXCLUDES) + tuple(excludes)
    skip = {Path(p).expanduser().resolve() for p in skip_paths}
    result = ScanResult(root=root_path)

    def on_error(exc: OSError) -> None:
        location = exc.filename or root_path
        try:
            relative = Path(location).resolve().relative_to(root_path).as_posix()
        except (OSError, ValueError):
            relative = ""
        if relative and relative != ".":
            result.unreadable.append(relative.rstrip("/") + "/")
        result.warnings.append(f"cannot scan {location}: {exc.strerror}")

    for dirpath, dirnames, filenames in os.walk(
        root_path, topdown=True, onerror=on_error, followlinks=False
    ):
        current = Path(dirpath)

        # Prune excluded directories so their contents are never visited.
        kept_dirs = []
        for name in sorted(dirnames):
            relative = (current / name).relative_to(root_path).as_posix()
            if not _is_excluded(relative, name, patterns):
                kept_dirs.append(name)
        dirnames[:] = kept_dirs

        for name in sorted(filenames):
            full_path = current / name
            relative = full_path.relative_to(root_path).as_posix()

            if _is_excluded(relative, name, patterns):
                continue
            # Symlinks could point outside the monitored tree, so they are
            # skipped rather than followed.
            if full_path.is_symlink():
                continue
            if full_path in skip:
                continue

            try:
                file_stat = full_path.stat()
            except OSError as exc:
                result.unreadable.append(relative)
                result.warnings.append(f"cannot stat {relative}: {exc.strerror}")
                continue

            if not stat.S_ISREG(file_stat.st_mode):
                continue

            try:
                digest = hash_file(full_path)
            except OSError as exc:
                result.unreadable.append(relative)
                result.warnings.append(f"cannot read {relative}: {exc.strerror}")
                continue

            result.files[relative] = FileRecord(
                path=relative,
                sha256=digest,
                size=file_stat.st_size,
                mtime=file_stat.st_mtime,
            )

    return result


def _is_excluded(relative: str, name: str, patterns: Iterable[str]) -> bool:
    return any(
        fnmatch.fnmatch(relative, pattern) or fnmatch.fnmatch(name, pattern)
        for pattern in patterns
    )
