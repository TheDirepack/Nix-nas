from __future__ import annotations

import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
LIB = ROOT / "scripts/lib"


class ZapAddonTests(unittest.TestCase):
    def setUp(self) -> None:
        script = LIB / "zap-addons.py"
        self.assertTrue(script.is_file(), "ZAP has no hash-locked add-on preparation")
        spec = importlib.util.spec_from_file_location("zap_addons", script)
        assert spec is not None and spec.loader is not None
        self.addons = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.addons)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        self.bundled = self.root / "bundled"
        self.bundled.mkdir()
        self.home = self.root / "home"
        self.content = b"fixture archive"
        self.row = {
            "id": "fixture",
            "version": "1.0.0",
            "status": "release",
            "archive": "fixture-release-1.zap",
            "sha256": hashlib.sha256(self.content).hexdigest(),
            "url": "https://github.com/zaproxy/zap-extensions/releases/download/fixture-v1/fixture-release-1.zap",
        }
        self.lock_path = self.root / "lock.json"
        self.write_lock([self.row])

    def write_lock(self, rows: list[dict]) -> None:
        self.lock_path.write_text(json.dumps({"schemaVersion": 1, "addons": rows}))

    def test_bundled_archive_is_verified_and_copied_without_download(self) -> None:
        (self.bundled / self.row["archive"]).write_bytes(self.content)
        lock = self.addons.load_lock(self.lock_path)
        with mock.patch.object(self.addons.subprocess, "run") as download:
            self.addons.prepare(lock, self.home, self.bundled)
        download.assert_not_called()
        self.assertEqual((self.home / "plugin" / self.row["archive"]).read_bytes(), self.content)

    def test_download_uses_only_the_locked_url_and_checks_bytes_before_publish(self) -> None:
        lock = self.addons.load_lock(self.lock_path)

        def download(command, **kwargs):
            self.assertIn("--fail", command)
            self.assertIn("--location", command)
            self.assertIn("--max-time", command)
            self.assertEqual(command[-1], self.row["url"])
            self.assertTrue(kwargs["check"])
            pathlib.Path(command[command.index("--output") + 1]).write_bytes(self.content)

        with mock.patch.object(self.addons.subprocess, "run", side_effect=download) as run:
            self.addons.prepare(lock, self.home, self.bundled)
        self.assertEqual(run.call_count, 1)
        self.assertEqual((self.home / "plugin" / self.row["archive"]).read_bytes(), self.content)

    def test_corrupt_download_is_fatal_and_does_not_publish_an_archive(self) -> None:
        lock = self.addons.load_lock(self.lock_path)

        def download(command, **_kwargs):
            pathlib.Path(command[command.index("--output") + 1]).write_bytes(b"wrong archive")

        with mock.patch.object(self.addons.subprocess, "run", side_effect=download):
            with self.assertRaisesRegex(ValueError, "SHA256"):
                self.addons.prepare(lock, self.home, self.bundled)
        self.assertEqual(list((self.home / "plugin").iterdir()), [])

    def test_corrupt_bundled_archive_is_fatal_without_live_fallback(self) -> None:
        (self.bundled / self.row["archive"]).write_bytes(b"wrong archive")
        lock = self.addons.load_lock(self.lock_path)
        with mock.patch.object(self.addons.subprocess, "run") as download:
            with self.assertRaisesRegex(ValueError, "SHA256"):
                self.addons.prepare(lock, self.home, self.bundled)
        download.assert_not_called()

    def test_lock_rejects_unsafe_filenames_duplicate_ids_and_unpinned_sources(self) -> None:
        variants = (
            {"archive": "../../escape.zap"},
            {"sha256": "not-a-digest"},
            {"url": "http://github.com/zaproxy/zap-extensions/releases/download/fixture-v1/fixture-release-1.zap"},
            {"url": "https://example.invalid/fixture.zap"},
            {"url": "https://github.com/zaproxy/zap-extensions/releases/latest/download/fixture-release-1.zap"},
        )
        for override in variants:
            with self.subTest(override=override):
                self.write_lock([{**self.row, **override}])
                with self.assertRaises(ValueError):
                    self.addons.load_lock(self.lock_path)
        self.write_lock([self.row, self.row])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.addons.load_lock(self.lock_path)

    def test_native_runnable_inventory_must_match_the_entire_lock(self) -> None:
        lock = self.addons.load_lock(self.lock_path)
        state = self.root / "add-ons-state.xml"
        for rows, accepted in (
            ([("fixture", "1.0.0")], True),
            ([], False),
            ([("fixture", "2.0.0")], False),
            ([("fixture", "1.0.0"), ("unexpected", "1.0.0")], False),
        ):
            with self.subTest(rows=rows):
                state.write_text(
                    "<addonsstate><runnableAddOns>"
                    + "".join(
                        f"<addon><id>{name}</id><fullversion>{version}</fullversion></addon>" for name, version in rows
                    )
                    + "</runnableAddOns></addonsstate>"
                )
                if accepted:
                    self.addons.verify_loaded(lock, state)
                else:
                    with self.assertRaisesRegex(ValueError, "runnable"):
                        self.addons.verify_loaded(lock, state)

    def test_native_state_rejects_doctypes_and_oversized_xml(self) -> None:
        lock = self.addons.load_lock(self.lock_path)
        state = self.root / "add-ons-state.xml"
        for declaration in (
            '<!DOCTYPE addonsstate [<!ENTITY version "1.0.0">]>',
            '<!DOCTYPE addonsstate SYSTEM "file:///must-not-read">',
        ):
            with self.subTest(declaration=declaration):
                state.write_text(
                    declaration + "<addonsstate><runnableAddOns><addon>"
                    "<id>fixture</id><fullversion>1.0.0</fullversion>"
                    "</addon></runnableAddOns></addonsstate>"
                )
                with self.assertRaisesRegex(ValueError, "DOCTYPE"):
                    self.addons.verify_loaded(lock, state)
        state.write_text(
            "<addonsstate><!--" + "x" * 65536 + "--><runnableAddOns><addon>"
            "<id>fixture</id><fullversion>1.0.0</fullversion>"
            "</addon></runnableAddOns></addonsstate>"
        )
        with self.assertRaisesRegex(ValueError, "size"):
            self.addons.verify_loaded(lock, state)

    def test_canonical_lock_preserves_both_beta_rule_sets_and_native_browser_dependencies(self) -> None:
        lock = self.addons.load_lock(LIB / "zap-addons.lock.json")
        by_id = {row["id"]: row for row in lock["addons"]}
        for name in (
            "pscanrules",
            "pscanrulesBeta",
            "ascanrules",
            "ascanrulesBeta",
            "client",
            "authhelper",
            "selenium",
            "automation",
            "commonlib",
            "network",
            "reports",
        ):
            self.assertIn(name, by_id)
        self.assertEqual(by_id["pscanrulesBeta"]["version"], "50.0.0")
        self.assertEqual(
            by_id["pscanrulesBeta"]["sha256"], "a979f7cd5d8be10e0338b417e006ec1e2f6ec79101010d570ddb5199892e921b"
        )

    def test_native_evidence_must_match_the_image_lock_and_entire_inventory(self) -> None:
        image = "fixture@sha256:" + "a" * 64
        evidence = self.root / "evidence.json"
        valid = {
            "image": image,
            "lockSha256": hashlib.sha256(self.lock_path.read_bytes()).hexdigest(),
            "runnableVerified": True,
            "addons": [self.row],
        }
        evidence.write_text(json.dumps(valid))
        verify = getattr(self.addons, "verify_evidence", None)
        self.assertIsNotNone(verify, "ZAP evidence is accepted without parsing its native inventory")
        assert verify is not None
        verify(self.lock_path, evidence, image)
        for override in (
            {"image": "unexpected image"},
            {"lockSha256": "0" * 64},
            {"runnableVerified": False},
            {"addons": []},
            {"addons": [self.row, self.row]},
            {"addons": [{**self.row, "sha256": "0" * 64}]},
        ):
            with self.subTest(override=override):
                evidence.write_text(json.dumps({**valid, **override}))
                with self.assertRaisesRegex(ValueError, "evidence"):
                    verify(self.lock_path, evidence, image)
        evidence.write_text("corrupt")
        with self.assertRaises(ValueError):
            verify(self.lock_path, evidence, image)


if __name__ == "__main__":
    unittest.main()
