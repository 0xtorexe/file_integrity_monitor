"""Module 4: Integrity Checker.

Compares the current scan with the baseline and classifies every difference as
a modification, an addition or a deletion.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .scanner import FileRecord


class ChangeKind(str, Enum):
    """The three kinds of change detected by the monitor."""

    MODIFIED = "modified"
    ADDED = "added"
    DELETED = "deleted"


@dataclass(frozen=True)
class Change:
    """A single difference between the baseline and the current scan."""

    kind: ChangeKind
    path: str
    before: FileRecord | None = None
    after: FileRecord | None = None


@dataclass
class ComparisonResult:
    """All differences found during a check."""

    changes: list[Change]
    unchanged: int

    @property
    def has_changes(self) -> bool:
        return bool(self.changes)

    def counts(self) -> dict[str, int]:
        counts = {kind.value: 0 for kind in ChangeKind}
        for change in self.changes:
            counts[change.kind.value] += 1
        return counts


def compare(
    baseline_files: dict[str, FileRecord],
    current_files: dict[str, FileRecord],
) -> ComparisonResult:
    """Compare two sets of records keyed by relative path."""
    changes: list[Change] = []
    unchanged = 0

    # The union catches files that only exist in one of the two snapshots.
    for relative in sorted(set(baseline_files) | set(current_files)):
        before = baseline_files.get(relative)
        after = current_files.get(relative)

        if before is not None and after is not None:
            if before.sha256 == after.sha256:
                unchanged += 1
            else:
                changes.append(
                    Change(ChangeKind.MODIFIED, relative, before=before, after=after)
                )
        elif before is not None:
            changes.append(Change(ChangeKind.DELETED, relative, before=before))
        else:
            changes.append(Change(ChangeKind.ADDED, relative, after=after))

    return ComparisonResult(changes=changes, unchanged=unchanged)
