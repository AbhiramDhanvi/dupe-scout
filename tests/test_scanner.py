import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from dupe_scout.scanner import _digest, _signature, scan


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, name, data=b"same content"):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def test_identical_content_different_names_and_nested_paths(self):
        self.write("one.bin")
        self.write("nested/two.txt")
        self.write("three.bin")
        result = scan([self.root])
        self.assertEqual(len(result.groups), 1)
        self.assertEqual(result.duplicate_files, 2)
        self.assertEqual(result.redundant_bytes, 24)
        self.assertEqual(result.files_hashed, 3)

    def test_equal_size_different_content_is_not_duplicate(self):
        self.write("a", b"abcd")
        self.write("b", b"abce")
        result = scan([self.root])
        self.assertFalse(result.groups)
        self.assertEqual(result.files_hashed, 2)

    def test_unique_sizes_are_not_hashed(self):
        self.write("a", b"a")
        self.write("b", b"ab")
        with patch("dupe_scout.scanner._digest") as digest:
            result = scan([self.root])
        digest.assert_not_called()
        self.assertEqual(result.files_scanned, 2)

    def test_empty_files_require_explicit_opt_in(self):
        self.write("a", b"")
        self.write("b", b"")
        self.assertEqual(scan([self.root]).files_scanned, 0)
        self.assertEqual(scan([self.root], min_size=0).duplicate_files, 1)

    def test_default_excludes_and_override(self):
        self.write("a")
        self.write(".git/b")
        self.write(".venv/c")
        self.assertFalse(scan([self.root]).groups)
        self.assertEqual(scan([self.root], excludes=[]).duplicate_files, 2)

    def test_glob_and_relative_path_excludes(self):
        self.write("keep/a")
        self.write("keep/b.tmp")
        self.write("cache/c")
        result = scan([self.root], excludes=["*.tmp", "cache/*"])
        self.assertEqual(result.files_scanned, 1)

    def test_multiple_and_overlapping_roots_are_not_double_counted(self):
        self.write("nested/a")
        self.write("b")
        result = scan([self.root, self.root / "nested", self.root])
        self.assertEqual(result.files_scanned, 2)
        self.assertEqual(result.duplicate_files, 1)

    def test_disjoint_roots_find_cross_directory_duplicates(self):
        self.write("left/a")
        self.write("right/b")
        self.assertEqual(scan([self.root / "left", self.root / "right"]).duplicate_files, 1)

    def test_hardlinks_do_not_inflate_redundancy(self):
        source = self.write("a")
        try:
            os.link(source, self.root / "alias")
        except OSError:
            self.skipTest("hard links unavailable")
        self.write("b")
        result = scan([self.root])
        self.assertEqual(result.skipped_hardlinks, 1)
        self.assertEqual(result.duplicate_files, 1)

    def test_symlinks_are_skipped(self):
        source = self.write("a")
        self.write("nested/b")
        try:
            (self.root / "alias").symlink_to(source)
            (self.root / "loop").symlink_to(self.root, target_is_directory=True)
        except OSError:
            self.skipTest("symlink creation unavailable")
        result = scan([self.root])
        self.assertEqual(result.skipped_links, 2)
        self.assertEqual(result.files_scanned, 2)

    def test_changed_file_is_rejected(self):
        path = self.write("a", b"original")
        snapshot = path.stat()
        path.write_bytes(b"a longer replacement")
        with self.assertRaisesRegex(OSError, "changed"):
            _digest(path, snapshot)

    @unittest.skipUnless(os.name == "nt", "Windows timestamp semantics")
    def test_windows_signature_does_not_compare_incompatible_ctime_values(self):
        info = self.write("a").stat()
        fields = {name: getattr(info, name) for name in (
            "st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")}
        fields["st_ctime_ns"] += 1000000
        self.assertEqual(_signature(info), _signature(SimpleNamespace(**fields)))

    def test_file_modified_while_hashing_is_rejected(self):
        import hashlib
        path = self.write("a")
        snapshot = path.stat()
        real_digest = hashlib.sha256()

        def update(chunk):
            real_digest.update(chunk)
            path.write_bytes(b"changed and longer")

        with patch("dupe_scout.scanner.hashlib.sha256") as constructor:
            constructor.return_value.update.side_effect = update
            with self.assertRaisesRegex(OSError, "changed during hashing"):
                _digest(path, snapshot)

    def test_hash_failure_is_reported_and_scan_continues(self):
        self.write("a")
        self.write("b")
        with patch("dupe_scout.scanner._digest", side_effect=PermissionError("denied")):
            result = scan([self.root])
        self.assertEqual(len(result.warnings), 2)
        self.assertFalse(result.groups)

    def test_larger_redundancy_is_sorted_first(self):
        for name in ("a", "b"):
            self.write(name, b"x")
        for name in ("c", "d"):
            self.write(name, b"large content")
        self.assertEqual(scan([self.root]).groups[0].size_bytes, 13)

    def test_invalid_roots_and_minimum(self):
        file = self.write("file")
        for roots in ([], [file], [self.root / "missing"]):
            with self.subTest(roots=roots), self.assertRaises(ValueError):
                scan(roots)
        with self.assertRaises(ValueError):
            scan([self.root], min_size=-1)

    def test_report_is_json_serializable_and_deterministic(self):
        self.write("a")
        self.write("b")
        first = json.dumps(scan([self.root]).to_dict(), sort_keys=True)
        second = json.dumps(scan([self.root]).to_dict(), sort_keys=True)
        self.assertEqual(first, second)
        self.assertEqual(json.loads(first)["schema_version"], 1)


if __name__ == "__main__":
    unittest.main()
