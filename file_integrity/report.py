"""Module 5: Alert and Report.

Turns a :class:`~file_integrity.checker.ComparisonResult` into either a
human-readable terminal report or a machine-readable dictionary.
"""

from __future__ import annotations

from datetime import datetime

from .baseline import Baseline
from .checker import Change, ChangeKind, ComparisonResult
from .scanner import FileRecord, ScanResult

RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"

_LABELS = {
    ChangeKind.MODIFIED: "MODIFIED",
    ChangeKind.ADDED: "ADDED",
    ChangeKind.DELETED: "DELETED",
}
_SYMBOLS = {
    ChangeKind.MODIFIED: "~",
    ChangeKind.ADDED: "+",
    ChangeKind.DELETED: "-",
}
_COLORS = {
    ChangeKind.MODIFIED: YELLOW,
    ChangeKind.ADDED: GREEN,
    ChangeKind.DELETED: RED,
}
_ORDER = {ChangeKind.MODIFIED: 0, ChangeKind.ADDED: 1, ChangeKind.DELETED: 2}
_DETAIL_INDENT = " " * 14


def render_report(
    comparison: ComparisonResult,
    baseline: Baseline,
    scan: ScanResult,
    *,
    color: bool = False,
) -> str:
    """Return the full terminal report as a string."""
    lines: list[str] = []
    lines.append(_paint("File Integrity Monitor", BOLD, color))
    lines.append(f"{'Root:':<11}{scan.root}")
    lines.append(f"{'Baseline:':<11}{baseline.path}")
    lines.append(f"{'Created:':<11}{_format_created(baseline.created)}")
    lines.append(f"{'Algorithm:':<11}{_format_algorithm(baseline.algorithm)}")
    lines.append("")

    for warning in scan.warnings:
        lines.append(_paint(f"WARNING: {warning}", YELLOW, color))
    if scan.warnings:
        lines.append("")

    if comparison.has_changes:
        for change in _ordered(comparison.changes):
            label = f"{_SYMBOLS[change.kind]} {_LABELS[change.kind]}"
            colored_label = _paint(f"{label:<10}", _COLORS[change.kind], color)
            lines.append(f"  {colored_label}  {change.path}")
            lines.extend(_detail_lines(change, color))
    else:
        files = "file matches" if comparison.unchanged == 1 else "files match"
        lines.append(
            _paint(
                f"No changes detected. All {comparison.unchanged} {files} "
                "the baseline.",
                GREEN,
                color,
            )
        )

    lines.append("")
    counts = comparison.counts()
    total = len(scan.files)
    files = "file" if total == 1 else "files"
    lines.append(
        f"Scanned {total} {files}: {counts['modified']} modified, "
        f"{counts['added']} added, {counts['deleted']} deleted, "
        f"{comparison.unchanged} unchanged"
    )
    if comparison.has_changes:
        lines.append(_paint("Result: CHANGES DETECTED", RED, color))
    else:
        lines.append(_paint("Result: OK", GREEN, color))

    return "\n".join(lines)


def report_as_dict(
    comparison: ComparisonResult,
    baseline: Baseline,
    scan: ScanResult,
) -> dict:
    """Return the report as JSON-serialisable data."""
    counts = comparison.counts()
    return {
        "root": str(scan.root),
        "baseline": {
            "path": str(baseline.path),
            "root": baseline.root,
            "created": baseline.created,
            "algorithm": baseline.algorithm,
        },
        "scanned_files": len(scan.files),
        "changes": [
            {
                "type": change.kind.value,
                "path": change.path,
                "before": _record_dict(change.before),
                "after": _record_dict(change.after),
            }
            for change in _ordered(comparison.changes)
        ],
        "summary": {
            "modified": counts["modified"],
            "added": counts["added"],
            "deleted": counts["deleted"],
            "unchanged": comparison.unchanged,
            "total_changes": len(comparison.changes),
        },
        "warnings": list(scan.warnings),
    }


def _ordered(changes: list[Change]) -> list[Change]:
    return sorted(changes, key=lambda change: (_ORDER[change.kind], change.path))


def _detail_lines(change: Change, color: bool) -> list[str]:
    lines: list[str] = []
    if change.kind is ChangeKind.MODIFIED and change.before and change.after:
        lines.append(
            f"{_DETAIL_INDENT}sha256 {_short_hash(change.before.sha256)} -> "
            f"{_paint(_short_hash(change.after.sha256), YELLOW, color)}"
        )
        lines.append(
            f"{_DETAIL_INDENT}size   {_format_size(change.before.size)} -> "
            f"{_format_size(change.after.size)}"
        )
    elif change.kind is ChangeKind.ADDED and change.after:
        lines.append(f"{_DETAIL_INDENT}sha256 {_short_hash(change.after.sha256)}")
        lines.append(f"{_DETAIL_INDENT}size   {_format_size(change.after.size)}")
    elif change.before:
        lines.append(f"{_DETAIL_INDENT}sha256 {_short_hash(change.before.sha256)}")
        lines.append(f"{_DETAIL_INDENT}size   {_format_size(change.before.size)}")
    return lines


def _record_dict(record: FileRecord | None) -> dict | None:
    if record is None:
        return None
    return {
        "sha256": record.sha256,
        "size": record.size,
        "modified_at": datetime.fromtimestamp(record.mtime).isoformat(
            timespec="seconds"
        ),
    }


def _paint(text: str, code: str, enabled: bool) -> str:
    return f"{code}{text}{RESET}" if enabled else text


def _short_hash(value: str) -> str:
    return f"{value[:12]}…" if len(value) > 12 else value


def _format_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


def _format_created(created: str) -> str:
    try:
        moment = datetime.fromisoformat(created)
    except ValueError:
        return created
    return moment.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z").strip()


def _format_algorithm(algorithm: str) -> str:
    return "SHA-256" if algorithm == "sha256" else algorithm.upper()


def format_baseline_summary(
    baseline: Baseline, scan: ScanResult, *, color: bool = False
) -> str:
    """Return the short message printed after creating a baseline."""
    lines = [
        _paint("Baseline created", BOLD, color),
        f"  File:      {baseline.path}",
        f"  Root:      {scan.root}",
        f"  Files:     {len(baseline.files)}",
        f"  Algorithm: {_format_algorithm(baseline.algorithm)}",
    ]
    for warning in scan.warnings:
        lines.append(f"  WARNING:   {warning}")
    return "\n".join(lines)
