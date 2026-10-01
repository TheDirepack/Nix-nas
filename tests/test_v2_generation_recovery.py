from __future__ import annotations

import contextlib
import io
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_entry as entry  # noqa: E402
import nas_v2_generation as generation  # noqa: E402


REV1 = "a" * 40
REV2 = "b" * 40

EFFECTIVE_V1 = '{"schemaVersion":3,"rev":1}\n'
EFFECTIVE_V2 = '{"schemaVersion":3,"rev":2}\n'


def _entry_env(runtime: pathlib.Path, repo: pathlib.Path) -> dict[str, str]:
    return {
        "NAS_V2_DESIRED": str(runtime.parent / "services.yaml"),
        "NAS_V2_SCHEMA": str(runtime.parent / "schema.json"),
        "NAS_V2_PLATFORM": str(runtime.parent / "platform.json"),
        "NAS_V2_EFFECTIVE": str(runtime / "effective.json"),
        "NAS_V2_PLAN": str(runtime / "plan.json"),
        "NAS_V2_PORTAL": str(runtime / "portal.json"),
        "NAS_V2_CADDY": str(runtime / "caddy-managed.conf"),
        "NAS_V2_SYSTEMD": str(runtime / "systemd"),
        "NAS_V2_BACKUP_INVENTORY": str(runtime / "backup-resources.json"),
        "NAS_V2_RESTIC_PATHS": str(runtime / "restic-v2-paths"),
        "NAS_V2_FIREWALLD": str(runtime / "firewalld"),
        "NAS_V2_HISTORY_REPOSITORY": str(repo),
        "NAS_V2_GIT_BIN": "git",
    }


def _seed_current(runtime: pathlib.Path, revision: str, effective_text: str) -> pathlib.Path:
    generations = runtime / "generations"
    candidate = generation.allocate_generation(generations, revision)
    (candidate / "effective.json").write_text(effective_text, encoding="utf-8")
    generation.publish_generation(
        candidate,
        expected_revision=revision,
        plan={"desiredRevision": revision},
        generation_root=generations,
        current_link=runtime / "current",
        compatibility_paths={runtime / "effective.json": pathlib.PurePosixPath("effective.json")},
    )
    return candidate


def _fake_apply(effective_text: str, revision: str):
    def _apply(*, paths, caddy, systemd, backup, firewalld, portal) -> dict:
        paths.effective.parent.mkdir(parents=True, exist_ok=True)
        paths.effective.write_text(effective_text, encoding="utf-8")
        return {"desiredRevision": revision}

    return _apply


class PublicationCleanupSeparationTests(unittest.TestCase):
    def test_prune_failure_after_publication_preserves_current_and_links(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = pathlib.Path(tmp) / "run"
            repo = pathlib.Path(tmp) / "repo"
            repo.mkdir()
            _seed_current(runtime, REV1, EFFECTIVE_V1)
            generations = runtime / "generations"
            discarded: list[str] = []
            real_discard = generation.discard_generation

            def _spy_discard(path: pathlib.Path, *, current_link: pathlib.Path) -> None:
                discarded.append(path.name)
                real_discard(path, current_link=current_link)

            def _flaky_prune(*args: object, **kwargs: object) -> list[pathlib.Path]:
                raise generation.GenerationError("injected post-publication prune failure")

            with (
                mock.patch.dict(os.environ, _entry_env(runtime, repo), clear=False),
                mock.patch.object(entry.sys, "argv", ["nas_v2_entry.py"]),
                mock.patch.object(entry, "ensure_bootstrap_applied", return_value={}),
                mock.patch.object(entry, "record_desired", return_value={"head": REV2}),
                mock.patch.object(entry, "_apply_once", side_effect=_fake_apply(EFFECTIVE_V2, REV2)),
                mock.patch.object(entry, "prune_generations", side_effect=_flaky_prune),
                mock.patch.object(entry, "discard_generation", side_effect=_spy_discard),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(1, entry.main())
            published = generations / REV2
            self.assertTrue(published.is_dir(), "post-publication prune failure must not discard current output")
            self.assertNotIn(REV2, discarded)
            self.assertEqual(published, (runtime / "current").resolve(strict=True))
            self.assertEqual(EFFECTIVE_V2, (runtime / "effective.json").read_text(encoding="utf-8"))

    def test_prune_retry_after_publication_failure_succeeds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = pathlib.Path(tmp) / "run"
            repo = pathlib.Path(tmp) / "repo"
            repo.mkdir()
            _seed_current(runtime, REV1, EFFECTIVE_V1)

            def _flaky_prune(*args: object, **kwargs: object) -> list[pathlib.Path]:
                raise generation.GenerationError("injected post-publication prune failure")

            patches = (
                mock.patch.dict(os.environ, _entry_env(runtime, repo), clear=False),
                mock.patch.object(entry.sys, "argv", ["nas_v2_entry.py"]),
                mock.patch.object(entry, "ensure_bootstrap_applied", return_value={}),
                mock.patch.object(entry, "record_desired", return_value={"head": REV2}),
                mock.patch.object(entry, "_apply_once", side_effect=_fake_apply(EFFECTIVE_V2, REV2)),
            )
            for patch in patches:
                patch.start()
                self.addCleanup(patch.stop)
            with mock.patch.object(entry, "prune_generations", side_effect=_flaky_prune):
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(1, entry.main())
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(0, entry.main())
            self.assertEqual(EFFECTIVE_V2, (runtime / "effective.json").read_text(encoding="utf-8"))
            self.assertTrue((runtime / "current").resolve(strict=True).is_dir())

    def test_pre_publication_failure_removes_only_its_unpublished_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = pathlib.Path(tmp) / "run"
            repo = pathlib.Path(tmp) / "repo"
            repo.mkdir()
            _seed_current(runtime, REV1, EFFECTIVE_V1)
            generations = runtime / "generations"

            def _failing_apply(*args: object, **kwargs: object) -> dict:
                raise RuntimeError("injected pre-publication apply failure")

            with (
                mock.patch.dict(os.environ, _entry_env(runtime, repo), clear=False),
                mock.patch.object(entry.sys, "argv", ["nas_v2_entry.py"]),
                mock.patch.object(entry, "ensure_bootstrap_applied", return_value={}),
                mock.patch.object(entry, "record_desired", return_value={"head": REV2}),
                mock.patch.object(entry, "_apply_once", side_effect=_failing_apply),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(1, entry.main())
            self.assertFalse((generations / REV2).exists(), "failed candidate must be cleaned up")
            self.assertEqual(generations / REV1, (runtime / "current").resolve(strict=True))
            self.assertEqual(EFFECTIVE_V1, (runtime / "effective.json").read_text(encoding="utf-8"))

    def test_failed_publish_retains_previous_current_as_recovery_material(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = pathlib.Path(tmp) / "run"
            repo = pathlib.Path(tmp) / "repo"
            repo.mkdir()
            _seed_current(runtime, REV1, EFFECTIVE_V1)
            generations = runtime / "generations"

            def _failing_publish(*args: object, **kwargs: object) -> pathlib.Path:
                raise generation.GenerationError("injected publication failure")

            with (
                mock.patch.dict(os.environ, _entry_env(runtime, repo), clear=False),
                mock.patch.object(entry.sys, "argv", ["nas_v2_entry.py"]),
                mock.patch.object(entry, "ensure_bootstrap_applied", return_value={}),
                mock.patch.object(entry, "record_desired", return_value={"head": REV2}),
                mock.patch.object(entry, "_apply_once", side_effect=_fake_apply(EFFECTIVE_V2, REV2)),
                mock.patch.object(entry, "publish_generation", side_effect=_failing_publish),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(1, entry.main())
            self.assertEqual(generations / REV1, (runtime / "current").resolve(strict=True))
            self.assertEqual(EFFECTIVE_V1, (runtime / "effective.json").read_text(encoding="utf-8"))

    def test_fsync_failure_after_sealing_removes_candidate_and_preserves_old_current(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = pathlib.Path(tmp) / "run"
            repo = pathlib.Path(tmp) / "repo"
            repo.mkdir()
            old_current = _seed_current(runtime, REV1, EFFECTIVE_V1)

            with (
                mock.patch.dict(os.environ, _entry_env(runtime, repo), clear=False),
                mock.patch.object(entry.sys, "argv", ["nas_v2_entry.py"]),
                mock.patch.object(entry, "ensure_bootstrap_applied", return_value={}),
                mock.patch.object(entry, "record_desired", return_value={"head": REV2}),
                mock.patch.object(entry, "_apply_once", side_effect=_fake_apply(EFFECTIVE_V2, REV2)),
                mock.patch.object(generation, "_fsync_directory", side_effect=OSError("injected fsync failure")),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(1, entry.main())

            self.assertFalse((runtime / "generations" / REV2).exists())
            self.assertEqual(old_current, (runtime / "current").resolve(strict=True))
            self.assertEqual(EFFECTIVE_V1, (runtime / "effective.json").read_text(encoding="utf-8"))

    def test_compatibility_link_failure_after_sealing_removes_candidate_and_preserves_old_current(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = pathlib.Path(tmp) / "run"
            repo = pathlib.Path(tmp) / "repo"
            repo.mkdir()
            old_current = _seed_current(runtime, REV1, EFFECTIVE_V1)
            real_replace = generation._replace_symlink

            def _fail_plan_link(path: pathlib.Path, target: str) -> None:
                if path == runtime / "plan.json":
                    raise OSError("injected compatibility-link failure")
                real_replace(path, target)

            with (
                mock.patch.dict(os.environ, _entry_env(runtime, repo), clear=False),
                mock.patch.object(entry.sys, "argv", ["nas_v2_entry.py"]),
                mock.patch.object(entry, "ensure_bootstrap_applied", return_value={}),
                mock.patch.object(entry, "record_desired", return_value={"head": REV2}),
                mock.patch.object(entry, "_apply_once", side_effect=_fake_apply(EFFECTIVE_V2, REV2)),
                mock.patch.object(generation, "_replace_symlink", side_effect=_fail_plan_link),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(1, entry.main())

            self.assertFalse((runtime / "generations" / REV2).exists())
            self.assertEqual(old_current, (runtime / "current").resolve(strict=True))
            self.assertEqual(EFFECTIVE_V1, (runtime / "effective.json").read_text(encoding="utf-8"))

    def test_discard_never_removes_published_current_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = pathlib.Path(tmp) / "run"
            published = _seed_current(runtime, REV1, EFFECTIVE_V1)
            with self.assertRaisesRegex(generation.GenerationError, "current generation"):
                generation.discard_generation(published, current_link=runtime / "current")
            self.assertTrue(published.is_dir(), "cleanup must refuse a published current generation")
            self.assertEqual(published, (runtime / "current").resolve(strict=True))
            self.assertEqual(EFFECTIVE_V1, (runtime / "effective.json").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
