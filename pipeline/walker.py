"""Walk a repository the way a reviewer would: skip vendored, generated and oversized files."""

from pathlib import Path

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "bower_components", ".venv", "venv", "__pycache__",
    ".tox", ".mypy_cache", ".pytest_cache", "vendor", "dist", "build", "target", ".next", "coverage",
}
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_FILES = 50_000


def walk(root, max_files=MAX_FILES, max_file_bytes=MAX_FILE_BYTES):
    """Return (files, skipped) where skipped counts what was left out and why.

    Large repositories are scanned up to the limits instead of failing outright.
    """
    root = Path(root)
    files = []
    skipped = {"largeFiles": 0, "overFileLimit": 0, "symlinks": 0}
    directories = [root]
    while directories:
        directory = directories.pop()
        try:
            entries = sorted(directory.iterdir())
        except OSError:
            continue
        for path in entries:
            if path.is_symlink():
                skipped["symlinks"] += 1
            elif path.is_dir():
                if path.name not in SKIP_DIRS:
                    directories.append(path)
            elif path.is_file():
                if path.stat().st_size > max_file_bytes:
                    skipped["largeFiles"] += 1
                elif len(files) >= max_files:
                    skipped["overFileLimit"] += 1
                else:
                    files.append(path)
    return sorted(files), skipped
