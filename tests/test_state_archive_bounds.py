from __future__ import annotations

import importlib.util
import io
import json
import os
import pathlib
import socket
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))
SPEC = importlib.util.spec_from_file_location("nas_state_bounds", ROOT / "services" / "nas_state.py")
assert SPEC and SPEC.loader
state = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = state
SPEC.loader.exec_module(state)


def _registry(public: pathlib.Path, sensitive: pathlib.Path, missing: pathlib.Path) -> str:
    return json.dumps(
        [
            {
                "name": "public",
                "source": str(public),
                "kind": "path",
                "sensitive": False,
                "optional": False,
                "restoreStrategy": "path-policy",
                "owner": "root",
                "group": "root",
                "rootMode": "0640",
            },
            {
                "name": "sensitive",
                "source": str(sensitive),
                "kind": "path",
                "sensitive": True,
                "optional": False,
                "restoreStrategy": "path-policy",
                "owner": "root",
                "group": "root",
                "rootMode": "0600",
            },
            {
                "name": "optional",
                "source": str(missing),
                "kind": "path",
                "sensitive": False,
                "optional": True,
                "restoreStrategy": "path-policy",
                "owner": "root",
                "group": "root",
                "rootMode": "0750",
            },
        ]
    )


def _env(registry: str) -> dict[str, str]:
    return {
        "NAS_STATE_ALLOW_UNPRIVILEGED": "1",
        "NAS_STATE_ALLOW_UNSIGNED": "1",
        "NAS_STATE_EXPORT_QUIESCE": "0",
        "NAS_STATE_REGISTRY_JSON": registry,
    }


class StateArchiveBoundTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = pathlib.Path(self._tmp.name)
        patch = mock.patch.multiple(
            state,
            DEFAULT_ROLLBACK_ROOT=root / "rollbacks",
            DEFAULT_RUNTIME_ROOT=root / "runtime",
            RESTORE_JOURNAL=root / "restore-operation.json",
        )
        patch.start()
        self.addCleanup(patch.stop)
        env_patch = mock.patch.dict(os.environ, {"NAS_STATE_RUNTIME_ROOT": str(root / "runtime")})
        env_patch.start()
        self.addCleanup(env_patch.stop)

    def completed(self, returncode: int = 0) -> mock.Mock:
        return mock.Mock(returncode=returncode, stdout="", stderr="")

    def test_many_empty_members_rejected_before_full_list_materialized(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            bundle = root / "many.tar.gz"
            with tarfile.open(bundle, "w:gz", format=tarfile.PAX_FORMAT) as archive:
                for index in range(50):
                    member = tarfile.TarInfo(f"payload/member-{index:03d}")
                    member.size = 0
                    member.mode = 0o644
                    member.mtime = 0
                    archive.addfile(member, io.BytesIO(b""))
            with mock.patch.object(state, "MAX_ARCHIVE_MEMBERS", 10):
                with mock.patch.object(
                    tarfile.TarFile, "getmembers", side_effect=AssertionError("must stream, not materialize")
                ):
                    with self.assertRaisesRegex(state.StateError, "too many archive members"):
                        state.validate_bundle(bundle)
            staging = root / "staging-should-not-exist"
            self.assertFalse(staging.exists())

    def test_metadata_heavy_headers_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            bundle = root / "heavy.tar.gz"
            with tarfile.open(bundle, "w:gz", format=tarfile.PAX_FORMAT) as archive:
                member = tarfile.TarInfo("payload/heavy")
                member.size = 1
                member.mode = 0o644
                member.mtime = 0
                member.pax_headers = {"comment": "x" * (256 * 1024)}
                archive.addfile(member, io.BytesIO(b"y"))
            with self.assertRaisesRegex(state.StateError, "metadata|header|too large"):
                state.validate_bundle(bundle)
            self.assertFalse(any((pathlib.Path(self._tmp.name) / "runtime").glob("nas-state-validate.*")))

    def test_long_names_duplicates_unsupported_truncation_and_size_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            long_bundle = root / "long.tar.gz"
            with tarfile.open(long_bundle, "w:gz") as archive:
                member = tarfile.TarInfo("payload/" + "a" * 5000)
                member.size = 0
                archive.addfile(member, io.BytesIO(b""))
            with self.assertRaisesRegex(state.StateError, "too long|Unsafe bundle path"):
                state.validate_bundle(long_bundle)

            dup_bundle = root / "dup.tar.gz"
            with tarfile.open(dup_bundle, "w:gz") as archive:
                for _ in range(2):
                    member = tarfile.TarInfo("payload/dup")
                    member.size = 3
                    member.mode = 0o644
                    member.mtime = 0
                    archive.addfile(member, io.BytesIO(b"abc"))
            with self.assertRaisesRegex(state.StateError, "duplicate"):
                state.validate_bundle(dup_bundle)

            unsupported = root / "unsupported.tar.gz"
            with tarfile.open(unsupported, "w:gz") as archive:
                member = tarfile.TarInfo("payload/link")
                member.type = tarfile.SYMTYPE
                member.linkname = "payload/target"
                member.mtime = 0
                archive.addfile(member)
            with self.assertRaisesRegex(state.StateError, "unsupported archive object"):
                state.validate_bundle(unsupported)

            truncated = root / "truncated.tar.gz"
            with tarfile.open(truncated, "w:gz") as archive:
                member = tarfile.TarInfo("payload/ok")
                member.size = 5
                member.mode = 0o644
                member.mtime = 0
                archive.addfile(member, io.BytesIO(b"hello"))
            raw = truncated.read_bytes()
            truncated.write_bytes(raw[: len(raw) // 2])
            with self.assertRaises(state.StateError):
                state.validate_bundle(truncated)

            big_bundle = root / "big.tar.gz"
            with tarfile.open(big_bundle, "w:gz") as archive:
                member = tarfile.TarInfo("payload/big")
                member.size = 4096
                member.mode = 0o644
                member.mtime = 0
                archive.addfile(member, io.BytesIO(b"x" * 4096))
            with mock.patch.object(state, "MAX_ARCHIVE_BYTES", 1024):
                with self.assertRaisesRegex(state.StateError, "extraction size limit"):
                    state.validate_bundle(big_bundle)

    def test_extraction_failure_removes_temporary_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            bundle = root / "mixed.tar.gz"
            with tarfile.open(bundle, "w:gz") as archive:
                for name in ("payload/good-a", "payload/good-b"):
                    member = tarfile.TarInfo(name)
                    member.size = 4
                    member.mode = 0o644
                    member.mtime = 0
                    archive.addfile(member, io.BytesIO(b"good"))
            destination = root / "destination"
            destination.mkdir()
            real_copy = state._copy_bounded
            calls = 0

            def flaky_copy(*args: object, **kwargs: object) -> int:
                nonlocal calls
                calls += 1
                if calls >= 2:
                    raise state.StateError("injected extraction failure")
                return real_copy(*args, **kwargs)

            with mock.patch.object(state, "_copy_bounded", side_effect=flaky_copy):
                with self.assertRaises(state.StateError):
                    state.extract_bundle(bundle, destination)
            self.assertEqual(2, calls)
            self.assertFalse((destination / "payload" / "good-a").exists())
            self.assertFalse((destination / "payload" / "good-b").exists())

    def test_bad_hmac_causes_no_restore_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            public = root / "public.txt"
            sensitive = root / "sensitive.txt"
            public.write_text("original\n", encoding="utf-8")
            sensitive.write_text("original-secret\n", encoding="utf-8")
            signing_key = root / "signing-key"
            signing_key.write_text("ab" * 32 + "\n", encoding="utf-8")
            os.chmod(signing_key, 0o600)
            registry = _registry(public, sensitive, root / "missing")
            bundle = root / "state.tar.gz"
            signed_env = _env(registry) | {
                "NAS_STATE_ALLOW_UNSIGNED": "0",
                "NAS_STATE_SIGNING_KEY": str(signing_key),
            }
            with mock.patch.dict(os.environ, signed_env, clear=False):
                state.export_bundle(bundle, include_sensitive=True)
                extracted = root / "extracted"
                state.extract_bundle(bundle, extracted)
                manifest_path = extracted / state.BUNDLE_MANIFEST
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                manifest["entries"][0]["digest"] = "0" * 64
                manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                tampered = root / "tampered.tar.gz"
                with tarfile.open(tampered, "w:gz") as archive:
                    archive.add(manifest_path, arcname=state.BUNDLE_MANIFEST)
                    archive.add(extracted / state.PAYLOAD_ROOT, arcname=state.PAYLOAD_ROOT)
                before_public = public.read_text(encoding="utf-8")
                with (
                    mock.patch.object(state, "DEFAULT_ROLLBACK_ROOT", root / "rollbacks"),
                    mock.patch.object(
                        state,
                        "run_systemctl",
                        side_effect=lambda *args, **kwargs: self.completed(
                            1 if args[:2] == ("is-active", "--quiet") else 0
                        ),
                    ),
                ):
                    with self.assertRaisesRegex(state.StateError, "signature"):
                        state.restore_bundle(
                            tampered,
                            confirm_host=socket.gethostname(),
                            allow_partial=False,
                            include_sensitive=True,
                        )
                self.assertEqual(before_public, public.read_text(encoding="utf-8"))
                self.assertEqual("original-secret\n", sensitive.read_text(encoding="utf-8"))

    def test_valid_small_bundles_validate_and_restore(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            public = root / "public.txt"
            sensitive = root / "sensitive.txt"
            public.write_text("v1\n", encoding="utf-8")
            sensitive.write_text("s1\n", encoding="utf-8")
            registry = _registry(public, sensitive, root / "missing")
            bundle = root / "state.tar.gz"
            with mock.patch.dict(os.environ, _env(registry), clear=False):
                state.export_bundle(bundle, include_sensitive=True)
                validated = state.validate_bundle(bundle)
                self.assertTrue(validated["complete"])
                public.write_text("mutated\n", encoding="utf-8")
                with (
                    mock.patch.object(state, "DEFAULT_ROLLBACK_ROOT", root / "rollbacks"),
                    mock.patch.object(
                        state,
                        "run_systemctl",
                        side_effect=lambda *args, **kwargs: self.completed(
                            1 if args[:2] == ("is-active", "--quiet") else 0
                        ),
                    ),
                ):
                    result = state.restore_bundle(
                        bundle,
                        confirm_host=socket.gethostname(),
                        allow_partial=False,
                        include_sensitive=True,
                    )
                self.assertTrue(result["ok"])
                self.assertEqual("v1\n", public.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
