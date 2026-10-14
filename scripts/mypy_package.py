"""Run mypy against the flat-layout `shaidra` package.

The repository root *is* the package (setuptools package-dir maps ``shaidra``
to ``.``), so ``mypy -p shaidra`` cannot discover it without a path entry that
contains a real ``shaidra/`` directory. This wrapper builds a temporary
junction (Windows) or symlink (POSIX) named ``shaidra`` that points at the
repo root. The shim lives on the same drive as the repo (Windows cannot
compute relative paths across mounts, which breaks mypy exclude matching).
Exit code is mypy's.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    # Same-drive parent: tempfile's default C: location breaks mypy on D: checkouts.
    tmp_parent = repo_root.parent
    with tempfile.TemporaryDirectory(prefix=".shaidra-mypy-", dir=tmp_parent) as tmp:
        shim = Path(tmp) / "shaidra"
        try:
            if os.name == "nt":
                import _winapi

                _winapi.CreateJunction(str(repo_root), str(shim))
            else:
                shim.symlink_to(repo_root, target_is_directory=True)
        except OSError as exc:
            print(f"failed to create mypy shim at {shim}: {exc}", file=sys.stderr)
            return 2
        env = os.environ.copy()
        existing = env.get("MYPYPATH", "")
        env["MYPYPATH"] = f"{tmp}{os.pathsep}{existing}" if existing else tmp
        # --no-incremental: cache keys mix the shim path with real paths across runs.
        return subprocess.call(
            [sys.executable, "-m", "mypy", "--no-incremental", "-p", "shaidra"],
            cwd=repo_root,
            env=env,
        )


if __name__ == "__main__":
    raise SystemExit(main())
