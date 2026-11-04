from __future__ import annotations

import os
import grp
import pathlib
import stat
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_generation as generation  # noqa: E402


REVISION = "a" * 40
READER_GROUP = grp.getgrgid(os.getgid()).gr_name


class ManagedServicesV2GenerationTests(unittest.TestCase):
    def test_publish_seals_generation_and_switches_stable_links(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = pathlib.Path(tmp) / "nas-control"
            generations = runtime / "generations"
            candidate = generation.allocate_generation(generations, REVISION)
            (candidate / "systemd" / "units").mkdir(parents=True)
            (candidate / "effective.json").write_text('{"schemaVersion":3}\n', encoding="utf-8")
            (candidate / "systemd" / "manifest.json").write_text('{"schemaVersion":1}\n', encoding="utf-8")

            published = generation.publish_generation(
                candidate,
                expected_revision=REVISION,
                plan={"desiredRevision": REVISION},
                generation_root=generations,
                current_link=runtime / "current",
                compatibility_paths={
                    runtime / "effective.json": pathlib.PurePosixPath("effective.json"),
                    runtime / "systemd": pathlib.PurePosixPath("systemd"),
                },
                reader_group=READER_GROUP,
            )

            self.assertEqual(published, candidate)
            self.assertEqual(os.readlink(runtime / "current"), f"generations/{REVISION}")
            self.assertEqual(os.readlink(runtime / "effective.json"), "current/effective.json")
            self.assertEqual(os.readlink(runtime / "systemd"), "current/systemd")
            self.assertEqual((runtime / "effective.json").read_text(encoding="utf-8"), '{"schemaVersion":3}\n')
            # Caddy reads caddy-managed.conf through the sealed generation
            # after publication, so the seal is group-readable (0o550/0o440)
            # by the consumer group, still non-writable and not world-readable.
            self.assertEqual(stat.S_IMODE(candidate.stat().st_mode), 0o550)
            self.assertEqual(stat.S_IMODE((candidate / "effective.json").stat().st_mode), 0o440)
            self.assertEqual(stat.S_IMODE((candidate / "systemd").stat().st_mode), 0o550)
            self.assertEqual(stat.S_IMODE(generations.stat().st_mode), 0o750)
            for path in (candidate, candidate / "effective.json", candidate / "systemd"):
                mode = path.stat().st_mode
                self.assertEqual(path.stat().st_gid, os.getgid())
                self.assertEqual(mode & 0o222, 0, "sealed generations must never be writable")
                self.assertEqual(mode & 0o007, 0, "sealed generations must never be world-accessible")
            # The generation root stays owner-writable so the transaction can
            # allocate the next revision, but the consumer group only traverses.
            self.assertEqual(generations.stat().st_gid, os.getgid())
            self.assertEqual(stat.S_IMODE(generations.stat().st_mode) & 0o027, 0)
            self.assertEqual(stat.S_IMODE(generations.stat().st_mode) & 0o007, 0)

    def test_owner_only_seal_remains_available_without_a_reader_group(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            candidate = generation.allocate_generation(pathlib.Path(tmp) / "generations", REVISION)
            (candidate / "nested").mkdir()
            (candidate / "nested" / "file").write_text("projection\n", encoding="utf-8")

            generation._seal_tree(candidate)

            self.assertEqual(stat.S_IMODE(candidate.stat().st_mode), 0o500)
            self.assertEqual(stat.S_IMODE((candidate / "nested").stat().st_mode), 0o500)
            self.assertEqual(stat.S_IMODE((candidate / "nested" / "file").stat().st_mode), 0o400)

    def test_missing_reader_group_fails_closed_before_publication(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = pathlib.Path(tmp) / "nas-control"
            generations = runtime / "generations"
            candidate = generation.allocate_generation(generations, REVISION)
            (candidate / "effective.json").write_text("{}\n", encoding="utf-8")

            with self.assertRaisesRegex(generation.GenerationError, "does not exist"):
                generation.publish_generation(
                    candidate,
                    expected_revision=REVISION,
                    plan={"desiredRevision": REVISION},
                    generation_root=generations,
                    current_link=runtime / "current",
                    compatibility_paths={runtime / "effective.json": pathlib.PurePosixPath("effective.json")},
                    reader_group="nas-v2-missing-readers",
                )
            self.assertFalse((runtime / "current").exists())
            self.assertFalse((runtime / "effective.json").exists())

    def test_repeated_revision_allocates_new_immutable_generation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "generations"
            first = generation.allocate_generation(root, REVISION)
            second = generation.allocate_generation(root, REVISION)
            self.assertEqual(first.name, REVISION)
            self.assertEqual(second.name, REVISION + "-2")

    def test_prune_keeps_current_and_two_previous_generations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = pathlib.Path(tmp) / "nas-control"
            root = runtime / "generations"
            candidates = []
            for index, revision in enumerate(("a", "b", "c", "d"), start=1):
                candidate = generation.allocate_generation(root, revision * 40)
                (candidate / "effective.json").write_text("{}\n", encoding="utf-8")
                os.utime(candidate, (index, index))
                candidates.append(candidate)
            current = runtime / "current"
            current.parent.mkdir(parents=True, exist_ok=True)
            current.symlink_to(os.path.relpath(candidates[0], current.parent))

            removed = generation.prune_generations(root, current_link=current, retain=3)

            self.assertEqual({path.name for path in removed}, {"b" * 40})
            self.assertTrue(candidates[0].exists(), "the active generation must never be pruned")
            self.assertTrue(candidates[2].exists())
            self.assertTrue(candidates[3].exists())

    def test_prune_rejects_a_current_link_outside_generation_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "generations"
            root.mkdir(parents=True)
            outside = pathlib.Path(tmp) / "outside"
            outside.mkdir()
            current = pathlib.Path(tmp) / "current"
            current.symlink_to(outside)
            with self.assertRaisesRegex(generation.GenerationError, "beneath the generation root"):
                generation.prune_generations(root, current_link=current)

    def test_prune_removes_sealed_nested_generations_without_unsealing_current(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = pathlib.Path(tmp)
            root = runtime / "generations"
            old = generation.allocate_generation(root, "b" * 40)
            active = generation.allocate_generation(root, REVISION)
            for candidate in (old, active):
                (candidate / "nested").mkdir()
                (candidate / "nested/file").write_text("projection", encoding="utf-8")
                generation._seal_tree(candidate)
            current = runtime / "current"
            current.symlink_to(active)
            removed = generation.prune_generations(root, current_link=current, retain=1)
            self.assertEqual(removed, [old])
            self.assertFalse(old.exists())
            self.assertEqual(stat.S_IMODE(active.stat().st_mode), 0o500)
            self.assertEqual((active / "nested/file").read_text(), "projection")

    def test_prune_still_reports_removal_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = pathlib.Path(tmp)
            root = runtime / "generations"
            old = generation.allocate_generation(root, "b" * 40)
            active = generation.allocate_generation(root, REVISION)
            current = runtime / "current"
            current.symlink_to(active)
            with mock.patch.object(generation.shutil, "rmtree", side_effect=PermissionError("denied")):
                with self.assertRaisesRegex(generation.GenerationError, "unable to prune"):
                    generation.prune_generations(root, current_link=current, retain=1)
            self.assertTrue(old.exists())
            self.assertEqual(current.resolve(), active)

    def test_relative_root_prune_preserves_current_and_retention_count(self) -> None:
        for retain in (1, 3):
            with self.subTest(retain=retain), tempfile.TemporaryDirectory() as tmp:
                runtime = pathlib.Path(tmp)
                root = runtime / "generations"
                candidates = [generation.allocate_generation(root, char * 40) for char in "abcd"]
                active = candidates[0]
                for index, candidate in enumerate(candidates):
                    (candidate / "file").write_bytes(b"projection\n")
                    generation._seal_tree(candidate)
                    os.utime(candidate, (index + 1, index + 1))
                current = runtime / "current"
                current.symlink_to(os.path.relpath(active, runtime))
                relative_root = pathlib.Path(os.path.relpath(root))
                removed = generation.prune_generations(relative_root, current_link=current, retain=retain)
                self.assertTrue(active.is_dir(), "relative roots must never delete the active generation")
                self.assertEqual(current.resolve(strict=True), active)
                self.assertEqual((active / "file").read_bytes(), b"projection\n")
                self.assertEqual(stat.S_IMODE(active.stat().st_mode), 0o500)
                self.assertEqual(len(list(root.iterdir())), retain)
                self.assertEqual(len(removed), 4 - retain)

    def test_revision_mismatch_never_switches_current(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = pathlib.Path(tmp) / "nas-control"
            root = runtime / "generations"
            candidate = generation.allocate_generation(root, REVISION)
            (candidate / "effective.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(generation.GenerationError, "changed while"):
                generation.publish_generation(
                    candidate,
                    expected_revision=REVISION,
                    plan={"desiredRevision": "b" * 40},
                    generation_root=root,
                    current_link=runtime / "current",
                    compatibility_paths={runtime / "effective.json": pathlib.PurePosixPath("effective.json")},
                )
            self.assertFalse((runtime / "current").exists())
            self.assertFalse((runtime / "effective.json").exists())

    def test_all_compatibility_paths_are_validated_before_sealing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = pathlib.Path(tmp) / "nas-control"
            root = runtime / "generations"
            candidate = generation.allocate_generation(root, REVISION)
            (candidate / "effective.json").write_text("{}\n", encoding="utf-8")
            outside = pathlib.Path(tmp) / "outside"

            with self.assertRaisesRegex(generation.GenerationError, "share the current-link parent"):
                generation.publish_generation(
                    candidate,
                    expected_revision=REVISION,
                    plan={"desiredRevision": REVISION},
                    generation_root=root,
                    current_link=runtime / "current",
                    compatibility_paths={
                        runtime / "effective.json": pathlib.PurePosixPath("effective.json"),
                        outside / "plan.json": pathlib.PurePosixPath("plan.json"),
                    },
                )

            self.assertEqual(0o700, stat.S_IMODE(candidate.stat().st_mode))
            self.assertFalse((runtime / "effective.json").exists())

    def test_invalid_revision_is_rejected_before_directory_creation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "generations"
            with self.assertRaisesRegex(generation.GenerationError, "invalid desired-state Git revision"):
                generation.allocate_generation(root, "../not-a-revision")
            self.assertFalse(root.exists())

    def test_discard_removes_only_unpublished_real_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "generations"
            candidate = generation.allocate_generation(root, REVISION)
            (candidate / "file").write_text("staged\n", encoding="utf-8")
            generation.discard_generation(candidate, current_link=pathlib.Path(tmp) / "current")
            self.assertFalse(candidate.exists())

    def test_discard_removes_a_sealed_candidate_that_is_not_current(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = pathlib.Path(tmp) / "nas-control"
            root = runtime / "generations"
            current = generation.allocate_generation(root, "b" * 40)
            candidate = generation.allocate_generation(root, REVISION)
            (candidate / "nested").mkdir()
            (candidate / "nested" / "file").write_text("staged\n", encoding="utf-8")
            generation._seal_tree(candidate)
            (runtime / "current").symlink_to(os.path.relpath(current, runtime))

            generation.discard_generation(candidate, current_link=runtime / "current")

            self.assertFalse(candidate.exists(), "filesystem mode must not be treated as publication state")

    def test_discard_categorically_refuses_current_generation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = pathlib.Path(tmp) / "nas-control"
            root = runtime / "generations"
            candidate = generation.allocate_generation(root, REVISION)
            (candidate / "file").write_text("published\n", encoding="utf-8")
            generation._seal_tree(candidate)
            (runtime / "current").symlink_to(os.path.relpath(candidate, runtime))

            with self.assertRaisesRegex(generation.GenerationError, "current generation"):
                generation.discard_generation(candidate, current_link=runtime / "current")

            self.assertTrue(candidate.is_dir())

    def test_generation_name_contract_accepts_full_allocator_range(self) -> None:
        for suffix in ("", "-2", "-9", "-10", "-19", "-100", "-999", "-1000", "-9999"):
            with self.subTest(suffix=suffix or "<bare>"):
                self.assertIsNotNone(
                    generation._GENERATION_NAME_RE.fullmatch(REVISION + suffix),
                    f"allocator suffix {suffix or '<bare>'} must be recognized",
                )
        for index in range(2, 10000):
            name = generation.format_generation_name(REVISION, index)
            self.assertIsNotNone(
                generation._GENERATION_NAME_RE.fullmatch(name), f"allocated suffix -{index} must be recognized"
            )

    def test_generation_name_contract_rejects_invalid_suffixes(self) -> None:
        for suffix in ("-0", "-1", "-01", "-1x", "-10000", "-", "-02", "--2"):
            with self.subTest(suffix=suffix):
                self.assertIsNone(
                    generation._GENERATION_NAME_RE.fullmatch(REVISION + suffix),
                    f"invalid suffix {suffix} must be rejected",
                )

    def test_format_and_parse_share_one_naming_contract(self) -> None:
        for index in (1, 2, 9, 10, 19, 100, 999, 1000, 9998, 9999):
            with self.subTest(index=index):
                name = generation.format_generation_name(REVISION, index)
                self.assertEqual((REVISION, index), generation.parse_generation_name(name))
        self.assertIsNone(generation.parse_generation_name(REVISION + "-10x"))
        self.assertIsNone(generation.parse_generation_name("not-a-generation"))
        with self.assertRaises(generation.GenerationError):
            generation.format_generation_name(REVISION, 0)
        with self.assertRaises(generation.GenerationError):
            generation.format_generation_name(REVISION, 10000)

    def test_many_allocations_remain_bounded_preserving_current(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = pathlib.Path(tmp) / "nas-control"
            root = runtime / "generations"
            allocated = [generation.allocate_generation(root, REVISION) for _ in range(25)]
            current = allocated[12]
            (current / "effective.json").write_text("{}\n", encoding="utf-8")
            generation.publish_generation(
                current,
                expected_revision=REVISION,
                plan={"desiredRevision": REVISION},
                generation_root=root,
                current_link=runtime / "current",
                compatibility_paths={runtime / "effective.json": pathlib.PurePosixPath("effective.json")},
            )
            removed = generation.prune_generations(root, current_link=runtime / "current", retain=3)
            remaining = {path.name for path in root.iterdir() if path.is_dir() and not path.is_symlink()}
            self.assertEqual(3, len(remaining))
            self.assertIn(current.name, remaining)
            self.assertEqual(len(allocated) - 3, len(removed))
            self.assertEqual(current, (runtime / "current").resolve(strict=True))
            self.assertEqual("{}\n", (runtime / "effective.json").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
