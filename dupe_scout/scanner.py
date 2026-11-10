"""Size-first, streaming SHA-256 duplicate detection using the standard library."""

from __future__ import annotations

import fnmatch
import hashlib
import os
import stat
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable

DEFAULT_EXCLUDES = (".git", ".venv", "venv", "__pycache__", "node_modules")
CHUNK_SIZE = 1024 * 1024


@dataclass(frozen=True)
class DuplicateGroup:
    sha256: str
    size_bytes: int
    paths: tuple[str, ...]

    @property
    def redundant_bytes(self) -> int:
        return self.size_bytes * (len(self.paths) - 1)


@dataclass
class ScanResult:
    roots: list[str]
    files_scanned: int = 0
    bytes_scanned: int = 0
    files_hashed: int = 0
    skipped_links: int = 0
    skipped_hardlinks: int = 0
    groups: list[DuplicateGroup] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def redundant_bytes(self) -> int:
        return sum(group.redundant_bytes for group in self.groups)

    @property
    def duplicate_files(self) -> int:
        """Number of extra copies, excluding one file per group."""
        return sum(len(group.paths) - 1 for group in self.groups)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["schema_version"] = 1
        data["duplicate_files"] = self.duplicate_files
        data["redundant_bytes"] = self.redundant_bytes
        for item, group in zip(data["groups"], self.groups):
            item["redundant_bytes"] = group.redundant_bytes
        return data


def _signature(info: os.stat_result) -> tuple:
    # Windows stat() and fstat() can expose different meanings for st_ctime
    # across Python versions. Size, mtime, type and identity remain comparable.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns if os.name != "nt" else None)


def _is_link(info: os.stat_result) -> bool:
    # Reparse points include Windows junctions and cloud placeholders.
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def _digest(path: Path, expected: os.stat_result) -> str:
    """Reject ordinary file changes observed before, during, or after hashing."""
    if _signature(path.lstat()) != _signature(expected):
        raise OSError("file changed since discovery")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or _signature(before) != _signature(expected):
            raise OSError("file changed before hashing")
        digest = hashlib.sha256()
        while chunk := stream.read(CHUNK_SIZE):
            digest.update(chunk)
        if _signature(os.fstat(stream.fileno())) != _signature(expected):
            raise OSError("file changed during hashing")
    if _signature(path.lstat()) != _signature(expected):
        raise OSError("file changed after hashing")
    return digest.hexdigest()


def scan(
    roots: Iterable[str | Path], *, min_size: int = 1,
    excludes: Iterable[str] = DEFAULT_EXCLUDES,
) -> ScanResult:
    """Scan directories without modifying files. Hash only equal-size candidates.

    Exclusions match a basename or a POSIX path relative to each root. Symlinks
    and Windows reparse points are skipped; hard links count as one physical file.
    """
    if min_size < 0:
        raise ValueError("minimum size must be non-negative")
    canonical: list[Path] = []
    for raw in roots:
        path = Path(raw).expanduser()
        try:
            info = path.lstat()
            if _is_link(info) or not stat.S_ISDIR(info.st_mode):
                raise ValueError(f"root must be a real directory: {path}")
            path = path.resolve(strict=True)
        except OSError as exc:
            raise ValueError(f"cannot access root {path}: {exc}") from exc
        if path not in canonical:
            canonical.append(path)
    if not canonical:
        raise ValueError("provide at least one directory")
    canonical.sort(key=str)
    result = ScanResult(roots=[str(path) for path in canonical])
    patterns = tuple(excludes)
    by_size: dict[int, list[tuple[Path, os.stat_result]]] = defaultdict(list)
    seen_paths: set[Path] = set()
    seen_files: set[tuple[int, int]] = set()

    def excluded(path: Path, root: Path) -> bool:
        relative = path.relative_to(root).as_posix()
        return any(fnmatch.fnmatchcase(path.name, pattern)
                   or fnmatch.fnmatchcase(relative, pattern) for pattern in patterns)

    def warn(exc: OSError) -> None:
        result.warnings.append(str(exc))

    for root in canonical:
        for directory, dirs, files in os.walk(root, topdown=True, onerror=warn, followlinks=False):
            parent = Path(directory)
            kept = []
            for name in sorted(dirs):
                path = parent / name
                if excluded(path, root):
                    continue
                try:
                    if _is_link(path.lstat()):
                        result.skipped_links += 1
                    else:
                        kept.append(name)
                except OSError as exc:
                    warn(exc)
            dirs[:] = kept
            for name in sorted(files):
                path = parent / name
                if path in seen_paths or excluded(path, root):
                    continue
                seen_paths.add(path)
                try:
                    info = path.lstat()
                    if _is_link(info):
                        result.skipped_links += 1
                        continue
                    if not stat.S_ISREG(info.st_mode) or info.st_size < min_size:
                        continue
                    identity = (info.st_dev, info.st_ino)
                    if info.st_ino and identity in seen_files:
                        result.skipped_hardlinks += 1
                        continue
                    if info.st_ino:
                        seen_files.add(identity)
                    result.files_scanned += 1
                    result.bytes_scanned += info.st_size
                    by_size[info.st_size].append((path, info))
                except OSError as exc:
                    warn(exc)

    for size, candidates in sorted(by_size.items()):
        if len(candidates) < 2:
            continue
        by_hash: dict[str, list[str]] = defaultdict(list)
        for path, info in candidates:
            try:
                digest = _digest(path, info)
                result.files_hashed += 1
                by_hash[digest].append(str(path))
            except OSError as exc:
                result.warnings.append(f"{path}: {exc}")
        for digest, paths in by_hash.items():
            if len(paths) > 1:
                result.groups.append(DuplicateGroup(digest, size, tuple(sorted(paths))))
    result.groups.sort(key=lambda group: (-group.redundant_bytes, group.paths))
    return result
