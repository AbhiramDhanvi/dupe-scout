"""Run from the repository root: python examples/demo.py."""

import subprocess
import sys
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory(prefix="dupe-scout-demo-") as folder:
    root = Path(folder)
    (root / "photos").mkdir()
    (root / "backups").mkdir()
    for name in ("photos/notes.txt", "backups/notes-copy.txt", "notes-final.txt"):
        (root / name).write_text("These files contain the same text.\n", encoding="utf-8", newline="\n")
    (root / "unique.txt").write_text("Only one copy of this text.\n", encoding="utf-8", newline="\n")
    subprocess.run([sys.executable, "-m", "dupe_scout", str(root)], check=True)
