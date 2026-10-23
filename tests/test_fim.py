"""Unit and command-line tests for the File Integrity Monitor."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from file_integrity.baseline import load_baseline, save_baseline
from file_integrity.checker import ChangeKind, compare
from file_integrity.errors import FimError
from file_integrity.hasher import hash_file
from file_integrity.scanner import scan_directory

REPO_ROOT = Path(__file__).resolve().parents[1]
FIM_SCRIPT = REPO_ROOT / "fim.py"
IS_ROOT = getattr(os, "geteuid", lambda: -1)() == 0


class TemporaryDirectoryTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self._temp_dir.name)
        self.addCleanup(self._temp_dir.cleanup)

    def write_file(self, relative: str, content: bytes = b"data") -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path


class HasherTests(TemporaryDirectoryTestCase):
    def test_known_digest(self) -> None:
        path = self.write_file("hello.txt", b"hello")
        expected = hashlib.sha256(b"hello").hexdigest()
        self.assertEqual(hash_file(path), expected)

    def test_empty_file(self) -> None:
        path = self.write_file("empty.bin", b"")
        self.assertEqual(
            hash_file(path), hashlib.sha256(b"").hexdigest()
        )

    def test_large_file(self) -> None:
        path = self.write_file("large.bin", b"x" * (3 * 1024 * 1024 + 17))
        self.assertEqual(hash_file(path), hashlib.sha256(path.read_bytes()).hexdigest())


class ScannerTests(TemporaryDirectoryTestCase):
    def test_finds_nested_files_with_relative_paths(self) -> None:
        self.write_file("a.txt", b"a")
        self.write_file("sub/b.txt", b"b")

        result = scan_directory(self.root)

        self.assertEqual(set(result.files), {"a.txt", "sub/b.txt"})
        self.assertEqual(result.files["a.txt"].size, 1)
        self.assertEqual(result.warnings, [])

    def test_excludes_glob_patterns(self) -> None:
        self.write_file("keep.txt")
        self.write_file("skip.log")
        self.write_file("cache/data.bin")

        result = scan_directory(
            self.root, excludes=["*.log", "cache/*"]
        )

        self.assertEqual(set(result.files), {"keep.txt"})

    def test_skips_baseline_and_symlinks(self) -> None:
        self.write_file("tracked.txt")
        self.write_file(".fim_baseline.json", b"{}")
        link = self.root / "link.txt"
        try:
            link.symlink_to(self.root / "tracked.txt")
        except OSError:
            self.skipTest("symlinks are not supported on this platform")

        result = scan_directory(self.root)

        self.assertEqual(set(result.files), {"tracked.txt"})

    def test_rejects_missing_directory(self) -> None:
        with self.assertRaises(FimError):
            scan_directory(self.root / "missing")

    def test_rejects_file_as_root(self) -> None:
        path = self.write_file("file.txt")
        with self.assertRaises(FimError):
            scan_directory(path)


class BaselineTests(TemporaryDirectoryTestCase):
    def test_save_and_load_round_trip(self) -> None:
        self.write_file("a.txt", b"alpha")
        self.write_file("sub/b.txt", b"beta")
        scan = scan_directory(self.root)
        path = self.root / "baseline.json"

        saved = save_baseline(path, scan)
        loaded = load_baseline(path)

        self.assertTrue(path.is_file())
        self.assertEqual(loaded.root, str(self.root))
        self.assertEqual(loaded.algorithm, "sha256")
        self.assertEqual(loaded.created, saved.created)
        self.assertEqual(loaded.files, scan.files)

        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(data["version"], 1)
        self.assertEqual(data["file_count"], 2)

    def test_missing_baseline_raises(self) -> None:
        with self.assertRaises(FimError):
            load_baseline(self.root / "nope.json")

    def test_invalid_json_raises(self) -> None:
        path = self.root / "baseline.json"
        path.write_text("{not json", encoding="utf-8")
        with self.assertRaises(FimError):
            load_baseline(path)

    def test_wrong_version_raises(self) -> None:
        path = self.root / "baseline.json"
        path.write_text(
            json.dumps({"version": 99, "algorithm": "sha256", "files": {}}),
            encoding="utf-8",
        )
        with self.assertRaises(FimError):
            load_baseline(path)

    def test_wrong_algorithm_raises(self) -> None:
        path = self.root / "baseline.json"
        path.write_text(
            json.dumps({"version": 1, "algorithm": "md5", "files": {}}),
            encoding="utf-8",
        )
        with self.assertRaises(FimError):
            load_baseline(path)

    def test_baseline_file_has_private_permissions(self) -> None:
        self.write_file("a.txt")
        scan = scan_directory(self.root)
        path = self.root / "baseline.json"
        save_baseline(path, scan)
        mode = path.stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)


class CheckerTests(TemporaryDirectoryTestCase):
    def snapshot(self) -> dict:
        return scan_directory(self.root).files

    def test_identical_snapshots_have_no_changes(self) -> None:
        self.write_file("a.txt")
        baseline = self.snapshot()

        result = compare(baseline, self.snapshot())

        self.assertFalse(result.has_changes)
        self.assertEqual(result.unchanged, 1)
        self.assertEqual(result.counts(), {
            "modified": 0, "added": 0, "deleted": 0
        })

    def test_detects_modified_added_and_deleted(self) -> None:
        self.write_file("modified.txt", b"before")
        self.write_file("deleted.txt", b"gone later")
        self.write_file("same.txt", b"unchanged")
        baseline = self.snapshot()

        self.write_file("modified.txt", b"after")
        (self.root / "deleted.txt").unlink()
        self.write_file("added.txt", b"new")

        result = compare(baseline, self.snapshot())
        by_path = {change.path: change for change in result.changes}

        self.assertTrue(result.has_changes)
        self.assertEqual(result.unchanged, 1)
        self.assertEqual(by_path["modified.txt"].kind, ChangeKind.MODIFIED)
        self.assertEqual(by_path["deleted.txt"].kind, ChangeKind.DELETED)
        self.assertEqual(by_path["added.txt"].kind, ChangeKind.ADDED)
        self.assertEqual(
            by_path["modified.txt"].before.sha256,
            hashlib.sha256(b"before").hexdigest(),
        )
        self.assertEqual(
            by_path["modified.txt"].after.sha256,
            hashlib.sha256(b"after").hexdigest(),
        )

    def test_touching_a_file_without_changing_content_is_not_a_change(self) -> None:
        path = self.write_file("a.txt", b"same")
        baseline = self.snapshot()
        os.utime(path, (1, 1))

        result = compare(baseline, self.snapshot())

        self.assertFalse(result.has_changes)

    def test_unreadable_file_is_not_falsely_deleted(self) -> None:
        path = self.write_file("locked.txt", b"secret")
        baseline = self.snapshot()
        if IS_ROOT:
            self.skipTest("root can read files regardless of permissions")
        path.chmod(0o000)
        self.addCleanup(path.chmod, 0o644)

        scan = scan_directory(self.root)
        current = {
            name: record
            for name, record in scan.files.items()
            if not scan.is_unreadable(name)
        }
        baseline_files = {
            name: record
            for name, record in baseline.items()
            if not scan.is_unreadable(name)
        }
        result = compare(baseline_files, current)

        self.assertTrue(scan.warnings)
        self.assertTrue(scan.is_unreadable("locked.txt"))
        self.assertFalse(result.has_changes)


class CliTests(TemporaryDirectoryTestCase):
    def run_cli(self, *arguments: str) -> subprocess.CompletedProcess:
        environment = dict(os.environ)
        environment["NO_COLOR"] = "1"
        return subprocess.run(
            [sys.executable, str(FIM_SCRIPT), *arguments],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
            env=environment,
            timeout=60,
        )

    def test_baseline_then_clean_check(self) -> None:
        self.write_file("a.txt", b"alpha")
        self.write_file("sub/b.txt", b"beta")

        created = self.run_cli("baseline", str(self.root))
        self.assertEqual(created.returncode, 0, created.stderr)
        self.assertIn("Baseline created", created.stdout)
        self.assertTrue((self.root / ".fim_baseline.json").is_file())

        checked = self.run_cli("check", str(self.root))
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertIn("No changes detected", checked.stdout)
        self.assertIn("Result: OK", checked.stdout)

    def test_check_reports_all_change_kinds_and_exit_code(self) -> None:
        self.write_file("modified.txt", b"before")
        self.write_file("deleted.txt", b"gone")
        self.write_file("same.txt", b"same")
        self.assertEqual(self.run_cli("baseline", str(self.root)).returncode, 0)

        self.write_file("modified.txt", b"after")
        (self.root / "deleted.txt").unlink()
        self.write_file("added.txt", b"new")

        checked = self.run_cli("check", str(self.root))

        self.assertEqual(checked.returncode, 1, checked.stderr)
        self.assertIn("MODIFIED", checked.stdout)
        self.assertIn("ADDED", checked.stdout)
        self.assertIn("DELETED", checked.stdout)
        self.assertIn("modified.txt", checked.stdout)
        self.assertIn("added.txt", checked.stdout)
        self.assertIn("deleted.txt", checked.stdout)
        self.assertIn("Result: CHANGES DETECTED", checked.stdout)

    def test_json_report(self) -> None:
        self.write_file("a.txt", b"one")
        self.assertEqual(self.run_cli("baseline", str(self.root)).returncode, 0)
        self.write_file("a.txt", b"two")
        self.write_file("b.txt", b"new")

        checked = self.run_cli("check", str(self.root), "--json")

        self.assertEqual(checked.returncode, 1, checked.stderr)
        report = json.loads(checked.stdout)
        self.assertEqual(report["summary"]["modified"], 1)
        self.assertEqual(report["summary"]["added"], 1)
        self.assertEqual(report["summary"]["deleted"], 0)
        self.assertEqual(report["summary"]["total_changes"], 2)
        paths = {change["path"] for change in report["changes"]}
        self.assertEqual(paths, {"a.txt", "b.txt"})

    def test_missing_baseline_is_an_error(self) -> None:
        self.write_file("a.txt")

        checked = self.run_cli("check", str(self.root))

        self.assertEqual(checked.returncode, 2)
        self.assertIn("baseline not found", checked.stderr)

    def test_existing_baseline_requires_force(self) -> None:
        self.write_file("a.txt")
        self.assertEqual(self.run_cli("baseline", str(self.root)).returncode, 0)

        refused = self.run_cli("baseline", str(self.root))
        self.assertEqual(refused.returncode, 2)
        self.assertIn("--force", refused.stderr)

        forced = self.run_cli("baseline", str(self.root), "--force")
        self.assertEqual(forced.returncode, 0, forced.stderr)

    def test_custom_baseline_path_and_excludes(self) -> None:
        self.write_file("a.txt", b"a")
        self.write_file("debug.log", b"log")
        baseline_path = self.root / "meta" / "baseline.json"

        created = self.run_cli(
            "baseline",
            str(self.root),
            "--baseline",
            str(baseline_path),
            "--exclude",
            "*.log",
        )
        self.assertEqual(created.returncode, 0, created.stderr)
        self.assertTrue(baseline_path.is_file())

        data = json.loads(baseline_path.read_text(encoding="utf-8"))
        self.assertEqual(set(data["files"]), {"a.txt"})

        checked = self.run_cli(
            "check",
            str(self.root),
            "--baseline",
            str(baseline_path),
            "--exclude",
            "*.log",
        )
        self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_unreadable_file_warns_instead_of_reporting_deletion(self) -> None:
        if IS_ROOT:
            self.skipTest("root can read files regardless of permissions")
        path = self.write_file("locked.txt", b"secret")
        self.assertEqual(self.run_cli("baseline", str(self.root)).returncode, 0)
        path.chmod(0o000)
        self.addCleanup(path.chmod, 0o644)

        checked = self.run_cli("check", str(self.root))

        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertIn("WARNING", checked.stdout)
        self.assertIn("locked.txt", checked.stdout)
        self.assertNotIn("DELETED", checked.stdout)

    def test_invalid_directory_is_an_error(self) -> None:
        result = self.run_cli("check", str(self.root / "missing"))
        self.assertEqual(result.returncode, 2)
        self.assertIn("does not exist", result.stderr)

    def test_moved_baseline_root_produces_warning(self) -> None:
        self.write_file("a.txt")
        baseline_path = self.root / "baseline.json"
        self.assertEqual(
            self.run_cli(
                "baseline", str(self.root), "--baseline", str(baseline_path)
            ).returncode,
            0,
        )

        moved = self.root / "moved"
        moved.mkdir()
        self.write_file("moved/a.txt")

        checked = self.run_cli(
            "check", str(moved), "--baseline", str(baseline_path)
        )
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertIn("different directory", checked.stdout)


if __name__ == "__main__":
    unittest.main()
