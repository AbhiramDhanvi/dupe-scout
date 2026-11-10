# Dupe Scout

**Find duplicate files. See redundant storage. Keep control of your data.**

Dupe Scout is an original Python command-line project that recursively finds
files with identical size and SHA-256 content hashes. It produces readable,
JSON, or CSV reports and never deletes or modifies scanned files.

No runtime dependencies. No account, API key, or network access needed.

## Quick start

Requires Python 3.11 or newer. Windows, Linux, and macOS are supported.

```bash
git clone https://github.com/AbhiramDhanvi/dupe-scout.git
cd dupe-scout
python -m pip install .
dupe-scout --help
dupe-scout "path/to/folder"
```

You can also run directly from the repository without installing:

```bash
python -m dupe_scout "path/to/folder"
python examples/demo.py
```

On Windows, `py` can replace `python` if that is how your Python is installed.
If the installed command is not on PATH, use `python -m dupe_scout`.

## What it does

- Scans one or more directories recursively, including nested folders.
- Groups files by size first, then hashes only possible matches.
- Reads files in 1 MiB chunks instead of loading entire files into memory.
- Reports duplicate groups, extra copies, and estimated redundant content bytes.
- Exports structured JSON or spreadsheet-friendly CSV.
- Skips symbolic links, Windows reparse points, and duplicate hard-link aliases.
- Detects ordinary file changes during scanning and reports unreadable files.
- Supports exclusion globs and minimum file sizes.
- Refuses to overwrite existing reports or input files.

## Examples

```bash
# Compare several directories, including duplicates across them.
dupe-scout "Photos" "Backups"

# Ignore small files and exclude temporary files and a relative folder.
dupe-scout "Downloads" --min-size 1048576 --exclude "*.tmp" --exclude "cache"

# Write a new JSON report. Parent directories must already exist.
dupe-scout "Downloads" --format json --output duplicates.json

# CSV has one row per matching file.
dupe-scout "Downloads" --format csv --output duplicates.csv

# Include zero-byte files (excluded by default).
dupe-scout "Downloads" --min-size 0

# Useful for scripts: exit 1 if duplicates exist.
dupe-scout "Downloads" --fail-on-duplicates
```

Default excluded basenames: `.git`, `.venv`, `venv`, `__pycache__`, and
`node_modules`. Add `--no-default-excludes` to scan them too. Exclusions are
case-sensitive shell globs matching a basename or a slash-separated path
relative to a supplied root. Excluded directories are pruned. Each supplied root
is scanned independently, so explicitly supplying an excluded subdirectory as a
root opts that root back in.

Example summary from the included temporary-data demo:

```text
DUPE SCOUT
==========
Scanned 4 files (133.0 B); hashed 3 size-matched candidates.
Found 1 duplicate groups, 2 extra copies.
Estimated redundant content: 70.0 B
```

The full text report includes paths and SHA-256 hashes for each group. Paths in
text reports are quoted and escaped so unusual filenames cannot inject terminal
control characters. JSON preserves their exact values after decoding.

## Use as a Python library

```python
from dupe_scout.scanner import scan

result = scan(["Downloads"], min_size=1024, excludes=["*.tmp", ".git"])
for group in result.groups:
    print(group.size_bytes, group.paths)
print(result.redundant_bytes)
```

`excludes` replaces the library defaults when supplied. The CLI's `--exclude`
adds to defaults. JSON includes `schema_version`, roots, scan counters, warnings,
duplicate groups, and redundant bytes; each group includes `sha256`,
`size_bytes`, `paths`, and `redundant_bytes`.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Scan completed, including scans with duplicates by default |
| `1` | Partial scan with warnings, or duplicates with `--fail-on-duplicates` |
| `2` | Invalid arguments, inaccessible root, or report-writing error |
| `130` | Interrupted with Ctrl+C |

Warnings go to stderr. JSON includes warnings; CSV contains file rows only.

## How matching works

1. Walk directories and collect regular-file sizes and filesystem metadata.
2. Ignore files with unique sizes; their content cannot match another file.
3. Stream each size-matched candidate through Python's standard-library
   [SHA-256 implementation](https://docs.python.org/3/library/hashlib.html).
4. Group matching hashes, then sort by redundant bytes and path.

Runtime is dominated by reading candidate bytes. Metadata storage is O(N) for
N discovered files; the hashing buffer has a fixed size. Output order is stable
for an unchanged filesystem.

SHA-256 hash equality is used as the matching criterion; this is not a separate
byte-for-byte comparison. Redundant bytes represent logical content, not a promise
of physically reclaimable disk space: compression, sparse files, deduplication,
and filesystem allocation affect real storage. Hard links are counted once when
the filesystem exposes a nonzero inode identifier.

Scans are snapshots, not filesystem locks. Metadata checks catch ordinary
concurrent changes, but the tool does not promise safety against a hostile process
replacing files or directory trees during a scan. Re-scan files before acting on
a report. Cloud placeholder files are skipped with other Windows reparse points.

## Development and tests

```bash
python -m unittest discover -s tests -v
python examples/demo.py
```

The standard-library test suite covers real duplicate detection, equal-size
nonduplicates, exclusions, empty files, overlapping roots, hard links, symlinks,
changed files, read errors, exports, exit codes, and overwrite protection.
Symlink tests skip when the operating system does not allow their creation.
GitHub Actions runs tests on Windows and Ubuntu with Python 3.11-3.14.

```text
dupe_scout/
  scanner.py       Scanning, hashing, and result models
  cli.py           Arguments and report formats
  __main__.py      python -m dupe_scout entry point
tests/             Scanner and CLI tests
examples/demo.py   Reproducible demo using temporary files
```

## License

MIT. This repository contains an original implementation; no third-party project
source code is copied into it.
