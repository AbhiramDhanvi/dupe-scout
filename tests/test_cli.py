import contextlib
import csv
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dupe_scout.cli import main, render
from dupe_scout.scanner import ScanResult


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "a.txt").write_text("hello", encoding="utf-8")
        (self.root / "b.txt").write_text("hello", encoding="utf-8")

    def invoke(self, *args):
        output, error = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            code = main([str(self.root), *args])
        return code, output.getvalue(), error.getvalue()

    def test_json_stdout_and_exit_codes(self):
        code, output, error = self.invoke("--format", "json")
        self.assertEqual(code, 0)
        self.assertFalse(error)
        self.assertEqual(json.loads(output)["redundant_bytes"], 5)
        self.assertEqual(self.invoke("--fail-on-duplicates")[0], 1)

    def test_csv_handles_commas_and_unicode(self):
        (self.root / "comma, cafe.txt").write_text("hello", encoding="utf-8")
        code, output, _ = self.invoke("--format", "csv")
        rows = list(csv.DictReader(io.StringIO(output)))
        self.assertEqual(code, 0)
        self.assertEqual(len(rows), 3)
        self.assertTrue(any(row["path"].endswith("comma, cafe.txt") for row in rows))

    def test_output_file_is_exclusive_and_input_is_untouched(self):
        target = self.root / "report.json"
        code, output, _ = self.invoke("--format", "json", "--output", str(target))
        self.assertEqual(code, 0)
        self.assertEqual(output, "")
        original = target.read_bytes()
        with self.assertRaises(SystemExit) as raised:
            self.invoke("--output", str(target))
        self.assertEqual(raised.exception.code, 2)
        self.assertEqual(target.read_bytes(), original)
        with self.assertRaises(SystemExit):
            self.invoke("--output", str(self.root / "a.txt"))
        self.assertEqual((self.root / "a.txt").read_text(), "hello")

    def test_negative_minimum_is_usage_error(self):
        with self.assertRaises(SystemExit) as raised:
            self.invoke("--min-size", "-1")
        self.assertEqual(raised.exception.code, 2)

    def test_warnings_make_partial_scan_nonzero(self):
        result = ScanResult(roots=[], warnings=["unreadable file"])
        with patch("dupe_scout.cli.scan", return_value=result):
            code, _, error = self.invoke()
        self.assertEqual(code, 1)
        self.assertIn("unreadable file", error)

    def test_text_empty_result(self):
        result = ScanResult(roots=[])
        self.assertIn("No duplicate files found", render(result, "text"))

    def test_module_entry_point(self):
        response = subprocess.run(
            [sys.executable, "-m", "dupe_scout", str(self.root), "--format", "json"],
            capture_output=True, text=True, check=True,
        )
        self.assertEqual(json.loads(response.stdout)["duplicate_files"], 1)


if __name__ == "__main__":
    unittest.main()
