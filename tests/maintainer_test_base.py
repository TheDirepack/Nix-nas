from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


class MaintainerScriptMixin:
    @classmethod
    def setUpClass(cls) -> None:
        parent_setup = getattr(super(), "setUpClass", None)
        if parent_setup is not None:
            parent_setup()
        cls._temporary = tempfile.TemporaryDirectory()
        cls.clean_root = pathlib.Path(cls._temporary.name) / "repo"
        shutil.copytree(
            ROOT,
            cls.clean_root,
            ignore=shutil.ignore_patterns(
                ".git",
                ".fuzz-crashes",
                ".pytest_cache",
                ".ruff_cache",
                ".mypy_cache",
                "__pycache__",
                "*.pyc",
                ".coverage",
                "coverage.json",
                "node_modules",
                "playwright-report",
                "test-results",
            ),
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls._temporary.cleanup()
        parent_teardown = getattr(super(), "tearDownClass", None)
        if parent_teardown is not None:
            parent_teardown()

    def run_clean(self, *command: str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        return subprocess.run(
            list(command),
            cwd=self.clean_root,
            env=env,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
