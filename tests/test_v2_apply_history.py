from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
SCHEMA = ROOT / "schemas" / "managed-services-v3.schema.json"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_apply as v2apply  # noqa: E402
import nas_v2_editor as editor  # noqa: E402


@unittest.skipUnless(shutil.which("git"), "git is required")
class V2ApplyHistoryTests(unittest.TestCase):
    def test_history_revision_and_compile_share_one_authority_lock(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            schema = root / "schema.json"
            schema.write_text(SCHEMA.read_text(encoding="utf-8"), encoding="utf-8")
            desired = root / "services.yaml"
            original = "schemaVersion: 3\nservices: {}\n"
            replacement = (
                "schemaVersion: 3\n"
                "services:\n"
                "  later:\n"
                "    name: Later\n"
                "    workload:\n"
                "      kind: daemon\n"
                "    runtime:\n"
                "      type: systemd\n"
                "      unit: later.service\n"
            )
            desired.write_text(original, encoding="utf-8")
            history = root / "history.git"
            paths = v2apply.ApplyPaths(
                desired=desired,
                schema=schema,
                platform=None,
                effective=root / "effective.json",
                plan=root / "plan.json",
                history_repository=history,
            )

            compile_entered = threading.Event()
            allow_compile = threading.Event()
            apply_result: dict[str, object] = {}
            apply_error: list[BaseException] = []
            edit_error: list[BaseException] = []
            original_compile = v2apply._compile_paths_inner

            def paused_compile(inner_paths: v2apply.ApplyPaths):
                compile_entered.set()
                if not allow_compile.wait(timeout=5):
                    raise RuntimeError("test timed out waiting to resume compilation")
                return original_compile(inner_paths)

            def run_apply() -> None:
                try:
                    apply_result.update(v2apply.apply(paths))
                except BaseException as exc:  # pragma: no cover - surfaced below
                    apply_error.append(exc)

            def run_edit() -> None:
                try:
                    editor.replace_document(
                        replacement,
                        desired_path=desired,
                        schema_path=schema,
                        platform_path=None,
                    )
                except BaseException as exc:  # pragma: no cover - surfaced below
                    edit_error.append(exc)

            with mock.patch("nas_v2_apply._compile_paths_inner", side_effect=paused_compile):
                apply_thread = threading.Thread(target=run_apply)
                apply_thread.start()
                self.assertTrue(compile_entered.wait(timeout=5))

                edit_thread = threading.Thread(target=run_edit)
                edit_thread.start()
                edit_thread.join(timeout=0.2)
                self.assertTrue(edit_thread.is_alive(), "editor write bypassed compiler authority lock")

                allow_compile.set()
                apply_thread.join(timeout=5)
                edit_thread.join(timeout=5)

            self.assertFalse(apply_thread.is_alive())
            self.assertFalse(edit_thread.is_alive())
            if apply_error:
                raise apply_error[0]
            if edit_error:
                raise edit_error[0]

            revision = str(apply_result["desiredRevision"])
            git_head = subprocess.check_output(
                ["git", f"--git-dir={history}", "rev-parse", "HEAD"],
                text=True,
            ).strip()
            committed = subprocess.check_output(
                [
                    "git",
                    f"--git-dir={history}",
                    f"--work-tree={root}",
                    "show",
                    "HEAD:services.yaml",
                ],
                text=True,
            )
            self.assertEqual(revision, git_head)
            self.assertEqual(committed, original)
            self.assertEqual(desired.read_text(encoding="utf-8"), replacement)


if __name__ == "__main__":
    unittest.main()
