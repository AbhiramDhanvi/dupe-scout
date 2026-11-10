"""Command-line parsing and report rendering."""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from pathlib import Path

from . import __version__
from .scanner import DEFAULT_EXCLUDES, ScanResult, scan


def human_size(value: int) -> str:
    amount = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if amount < 1024 or unit == "TiB":
            return f"{amount:.1f} {unit}"
        amount /= 1024
    raise AssertionError("unreachable")


def render(result: ScanResult, format_name: str) -> str:
    if format_name == "json":
        return json.dumps(result.to_dict(), indent=2, ensure_ascii=True) + "\n"
    if format_name == "csv":
        stream = io.StringIO(newline="")
        writer = csv.writer(stream)
        writer.writerow(["group", "sha256", "size_bytes", "path"])
        for index, group in enumerate(result.groups, 1):
            for path in group.paths:
                # Prevent spreadsheet formula interpretation in CSV viewers.
                safe_path = "'" + path if path.startswith(("=", "+", "-", "@", "\t", "\r")) else path
                writer.writerow([index, group.sha256, group.size_bytes, safe_path])
        return stream.getvalue()
    lines = ["DUPE SCOUT", "==========",
             f"Scanned {result.files_scanned} files ({human_size(result.bytes_scanned)}); "
             f"hashed {result.files_hashed} size-matched candidates.",
             f"Found {len(result.groups)} duplicate groups, {result.duplicate_files} extra copies.",
             f"Estimated redundant content: {human_size(result.redundant_bytes)}", ""]
    for index, group in enumerate(result.groups, 1):
        lines.append(f"Group {index}: {len(group.paths)} copies x {human_size(group.size_bytes)}")
        lines.append(f"  SHA-256: {group.sha256}")
        lines.extend(f"  {ascii(path)}" for path in group.paths)
        lines.append("")
    if not result.groups:
        lines.append("No duplicate files found.")
    lines.append(f"Skipped {result.skipped_links} links/reparse points and "
                 f"{result.skipped_hardlinks} hard-link aliases.")
    lines.append("Read-only scan. No files were changed.")
    return "\n".join(lines) + "\n"


def _nonnegative(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected an integer number of bytes") from exc
    if number < 0:
        raise argparse.ArgumentTypeError("minimum size must be non-negative")
    return number


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Find duplicate files by size and SHA-256. Never deletes files.")
    parser.add_argument("directories", nargs="+", type=Path, help="directories to scan recursively")
    parser.add_argument("--version", action="version", version=f"Dupe Scout {__version__}")
    parser.add_argument("--min-size", type=_nonnegative, default=1, metavar="BYTES",
                        help="minimum file size; use 0 to include empty files (default: 1)")
    parser.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                        help="exclude a basename or relative POSIX path; repeatable")
    parser.add_argument("--no-default-excludes", action="store_true",
                        help="also scan .git, virtual environments, caches, and node_modules")
    parser.add_argument("--format", choices=("text", "json", "csv"), default="text")
    parser.add_argument("--output", type=Path, help="write to a NEW report file; refuses overwrite")
    parser.add_argument("--fail-on-duplicates", action="store_true",
                        help="return exit code 1 when duplicate files are found")
    args = parser.parse_args(argv)
    excludes = ([] if args.no_default_excludes else list(DEFAULT_EXCLUDES)) + args.exclude
    try:
        if args.output and args.output.exists():
            raise ValueError(f"report already exists: {args.output}")
        result = scan(args.directories, min_size=args.min_size, excludes=excludes)
        report = render(result, args.format)
        if args.output:
            # Exclusive creation protects both existing reports and input files.
            with args.output.open("x", encoding="utf-8", newline="") as stream:
                stream.write(report)
        else:
            sys.stdout.write(report)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    except KeyboardInterrupt:
        print("Scan cancelled.", file=sys.stderr)
        return 130
    for warning in result.warnings:
        print(f"Warning: {ascii(warning)}", file=sys.stderr)
    return 1 if result.warnings or (args.fail_on_duplicates and result.groups) else 0
