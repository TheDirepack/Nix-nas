from __future__ import annotations

import os
import pathlib
import stat
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_generation as generation  # noqa: E402


REVISION = "a" * 40


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
            )

            self.assertEqual(published, candidate)
            self.assertEqual(os.readlink(runtime / "current"), f"generations/{REVISION}")
            self.assertEqual(os.readlink(runtime / "effective.json"), "current/effective.json")
            self.assertEqual(os.readlink(runtime / "systemd"), "current/systemd")
            self.assertEqual((runtime / "effective.json").read_text(encoding="utf-8"), '{"schemaVersion":3}\n')
            self.assertEqual(stat.S_IMODE(candidate.stat().st_mode), 0o555)
            self.assertEqual(stat.S_IMODE((candidate / "effective.json").stat().st_mode), 0o444)
            self.assertEqual(stat.S_IMODE((candidate / "systemd").stat().st_mode), 0o555)

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
            generation.discard_generation(candidate)
            self.assertFalse(candidate.exists())

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
