from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import pathlib
import socket
import subprocess
import sys
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))
SPEC = importlib.util.spec_from_file_location("nas_state", ROOT / "services" / "nas_state.py")
assert SPEC and SPEC.loader
state = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = state
SPEC.loader.exec_module(state)


class StateBundleTests(unittest.TestCase):
    def registry(self, public: pathlib.Path, sensitive: pathlib.Path, missing: pathlib.Path) -> str:
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

    def environment(self, registry: str) -> dict[str, str]:
        return {
            "NAS_STATE_ALLOW_UNPRIVILEGED": "1",
            "NAS_STATE_ALLOW_UNSIGNED": "1",
            "NAS_STATE_EXPORT_QUIESCE": "0",
            "NAS_STATE_REGISTRY_JSON": registry,
        }

    def completed(self, returncode: int = 0) -> mock.Mock:
        return mock.Mock(returncode=returncode, stdout="", stderr="")

    def test_state_export_uses_appliance_coordinator_or_valid_parent_proof(self) -> None:
        args = SimpleNamespace(command="export", output=pathlib.Path("/tmp/state.tar.gz"), include_sensitive=False)
        with (
            mock.patch.object(state, "parser") as parser,
            mock.patch.object(state, "acquire_operation", return_value=contextlib.nullcontext()) as acquire,
            mock.patch.object(state, "export_bundle", return_value={"ok": True}),
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch("builtins.print"),
        ):
            parser.return_value.parse_args.return_value = args
            state.main()
        acquire.assert_called_once_with("state-export", ("appliance",))

        with (
            mock.patch.object(state, "parser") as parser,
            mock.patch.object(state, "acquire_operation") as acquire,
            mock.patch.object(state, "validate_coordination_token", return_value=None) as validate,
            mock.patch.object(state, "export_bundle", return_value={"ok": True}),
            mock.patch.dict(os.environ, {state.COORDINATION_TOKEN_ENV: "a" * 32}, clear=True),
            mock.patch("builtins.print"),
        ):
            parser.return_value.parse_args.return_value = args
            state.main()
        validate.assert_called_once_with("a" * 32, ("appliance",))
        acquire.assert_not_called()

    @unittest.skipIf(
        os.environ.get("GITHUB_ACTIONS") == "true" and not pathlib.Path("/run/nas-operations").exists(),
        "requires VM with /run/nas-operations tmpfs (host hermetic fallback cannot fully emulate nested operation lock)",
    )
    def test_real_nested_operation_runner_accepts_state_validator_success_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            operation_root = pathlib.Path(temporary) / "operations"
            operation_root.mkdir(mode=0o700)
            child = (
                "import sys; from unittest import mock; import nas_state as state; "
                "sys.argv=['nas-state','export','/tmp/nas-state-contract-test.tar.gz']; "
                "patch=mock.patch.object(state,'export_bundle',return_value={'ok': True}); "
                "patch.start(); state.main(); patch.stop()"
            )
            environment = os.environ.copy()
            environment["NAS_OPERATION_ROOT"] = str(operation_root)
            environment["PYTHONPATH"] = str(ROOT / "services")
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "services" / "nas_operation_lock.py"),
                    "--action",
                    "nested-state-contract",
                    "--class",
                    "appliance",
                    "--",
                    sys.executable,
                    "-c",
                    child,
                ],
                env=environment,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr or result.stdout)

    def test_state_nested_coordination_proof_fails_closed(self) -> None:
        args = SimpleNamespace(command="export", output=pathlib.Path("/tmp/state.tar.gz"), include_sensitive=False)
        with (
            mock.patch.object(state, "parser") as parser,
            mock.patch.object(
                state, "validate_coordination_token", side_effect=state.OperationBusyError("coordination proof is invalid")
            ),
            mock.patch.object(state, "export_bundle") as export,
            mock.patch.dict(os.environ, {state.COORDINATION_TOKEN_ENV: "0" * 32}, clear=True),
            mock.patch("builtins.print"),
        ):
            parser.return_value.parse_args.return_value = args
            with self.assertRaises(SystemExit) as raised:
                state.main()
        self.assertEqual(1, raised.exception.code)
        export.assert_not_called()

    def test_export_validate_and_diff_preserve_private_state_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            public = root / "public"
            public.mkdir(mode=0o750)
            (public / "settings.json").write_text('{"mode":"always"}\n', encoding="utf-8")
            sensitive = root / "secret.txt"
            sensitive.write_text("secret\n", encoding="utf-8")
            os.chmod(sensitive, 0o600)
            bundle = root / "state.tar.gz"
            registry = self.registry(public, sensitive, root / "missing")
            with mock.patch.dict(os.environ, self.environment(registry), clear=False):
                manifest = state.export_bundle(bundle, include_sensitive=False)
                self.assertFalse(manifest["complete"])
                self.assertEqual(0o600, bundle.stat().st_mode & 0o777)
                validated = state.validate_bundle(bundle)
                self.assertEqual(state.SCHEMA_VERSION, validated["schemaVersion"])
                result, drift = state.compare_bundle(bundle)
                self.assertFalse(drift)
                self.assertEqual("indeterminate", result["result"])
                self.assertEqual(
                    "omitted-sensitive",
                    next(row["status"] for row in result["authorities"] if row["name"] == "sensitive"),
                )
                (root / "missing").write_text("unexpected", encoding="utf-8")
                result, drift = state.compare_bundle(bundle)
                self.assertTrue(drift)
                self.assertEqual(
                    "drift", next(row["status"] for row in result["authorities"] if row["name"] == "optional")
                )
                (root / "missing").unlink()
                (public / "settings.json").write_text('{"mode":"off"}\n', encoding="utf-8")
                result, drift = state.compare_bundle(bundle)
                self.assertTrue(drift)
                self.assertEqual(
                    "drift", next(row["status"] for row in result["authorities"] if row["name"] == "public")
                )

    def test_complete_bundle_restores_files_and_creates_rollback_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            public = root / "public.txt"
            sensitive = root / "sensitive.txt"
            public.write_text("original-public\n", encoding="utf-8")
            sensitive.write_text("original-sensitive\n", encoding="utf-8")
            os.chmod(public, 0o640)
            os.chmod(sensitive, 0o600)
            bundle = root / "state.tar.gz"
            registry = self.registry(public, sensitive, root / "missing")
            with mock.patch.dict(os.environ, self.environment(registry), clear=False):
                manifest = state.export_bundle(bundle, include_sensitive=True)
                self.assertTrue(manifest["complete"])
                public.write_text("mutated-public\n", encoding="utf-8")
                sensitive.write_text("mutated-sensitive\n", encoding="utf-8")
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
                self.assertEqual("original-public\n", public.read_text(encoding="utf-8"))
                self.assertEqual("original-sensitive\n", sensitive.read_text(encoding="utf-8"))
                self.assertEqual(0o640, public.stat().st_mode & 0o777)
                rollback = pathlib.Path(result["rollbackBundle"])
                self.assertTrue(rollback.is_file())
                with mock.patch.dict(os.environ, self.environment(registry), clear=False):
                    rollback_manifest = state.validate_bundle(rollback)
                self.assertTrue(rollback_manifest["complete"])

    def test_restore_rolls_back_when_post_restore_activation_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            public = root / "public.txt"
            sensitive = root / "sensitive.txt"
            public.write_text("bundle\n", encoding="utf-8")
            sensitive.write_text("bundle-secret\n", encoding="utf-8")
            bundle = root / "state.tar.gz"
            registry = self.registry(public, sensitive, root / "missing")
            with mock.patch.dict(os.environ, self.environment(registry), clear=False):
                state.export_bundle(bundle, include_sensitive=True)
                public.write_text("pre-restore\n", encoding="utf-8")
                sensitive.write_text("pre-restore-secret\n", encoding="utf-8")
                calls = 0

                def systemctl(*args: str, **_kwargs: object) -> mock.Mock:
                    nonlocal calls
                    calls += 1
                    if args == ("daemon-reload",):
                        raise state.StateError("activation failed")
                    return self.completed(1 if args[:2] == ("is-active", "--quiet") else 0)

                with (
                    mock.patch.object(state, "DEFAULT_ROLLBACK_ROOT", root / "rollbacks"),
                    mock.patch.object(state, "run_systemctl", side_effect=systemctl),
                ):
                    with self.assertRaisesRegex(state.StateError, "activation failed"):
                        state.restore_bundle(
                            bundle,
                            confirm_host=socket.gethostname(),
                            allow_partial=False,
                            include_sensitive=True,
                        )
                self.assertGreater(calls, 2)
                self.assertEqual("pre-restore\n", public.read_text(encoding="utf-8"))
                self.assertEqual("pre-restore-secret\n", sensitive.read_text(encoding="utf-8"))

    def test_restore_requires_matching_host_and_sensitive_opt_in(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            public = root / "public"
            sensitive = root / "sensitive"
            public.write_text("public", encoding="utf-8")
            sensitive.write_text("sensitive", encoding="utf-8")
            bundle = root / "state.tar.gz"
            registry = self.registry(public, sensitive, root / "missing")
            with mock.patch.dict(os.environ, self.environment(registry), clear=False):
                state.export_bundle(bundle, include_sensitive=True)
                with self.assertRaisesRegex(state.StateError, "hostname"):
                    state.restore_bundle(
                        bundle, confirm_host="not-this-host", allow_partial=False, include_sensitive=True
                    )
                with self.assertRaisesRegex(state.StateError, "include-sensitive"):
                    state.restore_bundle(
                        bundle, confirm_host=socket.gethostname(), allow_partial=False, include_sensitive=False
                    )

    def test_archive_member_names_reject_controls_and_filesystem_length_abuse(self) -> None:
        for raw in ["payload/\x00secret", "payload/line\nbreak", "payload/" + "a" * 256, "a" * 4097]:
            with self.subTest(raw=repr(raw)), self.assertRaisesRegex(state.StateError, "Unsafe bundle path"):
                state.safe_member_name(raw)

    def test_validate_rejects_path_traversal_and_source_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            malicious = root / "malicious.tar.gz"
            data = b"escape"
            with tarfile.open(malicious, "w:gz") as archive:
                member = tarfile.TarInfo("../escape")
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
            with self.assertRaisesRegex(state.StateError, "Unsafe bundle path"):
                state.validate_bundle(malicious)

            target = root / "target"
            target.write_text("value", encoding="utf-8")
            linked = root / "linked"
            linked.symlink_to(target)
            registry = json.dumps(
                [
                    {
                        "name": "linked",
                        "source": str(linked),
                        "kind": "path",
                        "sensitive": False,
                        "optional": False,
                        "restoreStrategy": "path-policy",
                        "owner": "root",
                        "group": "root",
                        "rootMode": "0750",
                    }
                ]
            )
            with mock.patch.dict(os.environ, self.environment(registry), clear=False):
                with self.assertRaisesRegex(state.StateError, "symlink"):
                    state.export_bundle(root / "linked.tar.gz", include_sensitive=False)

    def test_validation_rejects_forged_completeness_and_missing_authorities(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            public = root / "public"
            sensitive = root / "sensitive"
            public.write_text("public", encoding="utf-8")
            sensitive.write_text("sensitive", encoding="utf-8")
            registry = self.registry(public, sensitive, root / "optional")
            bundle = root / "valid.tar.gz"
            with mock.patch.dict(os.environ, self.environment(registry), clear=False):
                state.export_bundle(bundle, include_sensitive=True)
                extracted = root / "extracted"
                state.extract_bundle(bundle, extracted)
                manifest_path = extracted / state.BUNDLE_MANIFEST
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                manifest["entries"] = []
                manifest["complete"] = True
                manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                forged = root / "forged.tar.gz"
                with tarfile.open(forged, "w:gz") as archive:
                    archive.add(manifest_path, arcname=state.BUNDLE_MANIFEST)
                    archive.add(extracted / state.PAYLOAD_ROOT, arcname=state.PAYLOAD_ROOT)
                with self.assertRaisesRegex(state.StateError, "exact authority set"):
                    state.validate_bundle(forged)

    def test_signed_bundle_rejects_manifest_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            public = root / "public"
            sensitive = root / "sensitive"
            public.write_text("public", encoding="utf-8")
            sensitive.write_text("sensitive", encoding="utf-8")
            signing_key = root / "signing-key"
            signing_key.write_text("ab" * 32 + "\n", encoding="utf-8")
            os.chmod(signing_key, 0o600)
            registry = self.registry(public, sensitive, root / "optional")
            environment = self.environment(registry) | {
                "NAS_STATE_ALLOW_UNSIGNED": "0",
                "NAS_STATE_SIGNING_KEY": str(signing_key),
            }
            bundle = root / "valid.tar.gz"
            with mock.patch.dict(os.environ, environment, clear=False):
                state.export_bundle(bundle, include_sensitive=True)
                extracted = root / "extracted"
                state.extract_bundle(bundle, extracted)
                manifest_path = extracted / state.BUNDLE_MANIFEST
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                manifest["complete"] = not manifest["complete"]
                manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                tampered = root / "tampered.tar.gz"
                with tarfile.open(tampered, "w:gz") as archive:
                    archive.add(manifest_path, arcname=state.BUNDLE_MANIFEST)
                    archive.add(extracted / state.PAYLOAD_ROOT, arcname=state.PAYLOAD_ROOT)
                with self.assertRaisesRegex(state.StateError, "signature verification failed"):
                    state.validate_bundle(tampered)

    def test_restore_absence_requires_explicit_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            public = root / "public"
            sensitive = root / "sensitive"
            optional = root / "optional"
            public.write_text("public", encoding="utf-8")
            sensitive.write_text("sensitive", encoding="utf-8")
            registry = self.registry(public, sensitive, optional)
            bundle = root / "state.tar.gz"
            with mock.patch.dict(os.environ, self.environment(registry), clear=False):
                state.export_bundle(bundle, include_sensitive=True)
                optional.write_text("appeared", encoding="utf-8")
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
                    with self.assertRaisesRegex(state.StateError, "restore-absence"):
                        state.restore_bundle(
                            bundle,
                            confirm_host=socket.gethostname(),
                            allow_partial=False,
                            include_sensitive=True,
                        )
                self.assertTrue(optional.exists())

    def test_restore_preserves_existing_subpath_modes_instead_of_flattening_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            source = root / "source"
            destination = root / "destination"
            source.mkdir(mode=0o755)
            destination.mkdir(mode=0o750)
            (source / "private.txt").write_text("restored", encoding="utf-8")
            (source / "public.txt").write_text("restored", encoding="utf-8")
            (destination / "private.txt").write_text("old", encoding="utf-8")
            (destination / "public.txt").write_text("old", encoding="utf-8")
            os.chmod(source / "private.txt", 0o644)
            os.chmod(source / "public.txt", 0o600)
            os.chmod(destination / "private.txt", 0o600)
            os.chmod(destination / "public.txt", 0o640)
            authority = state.Authority("tree", str(destination), sensitive=False)
            state.restore_path(source, destination, authority)
            self.assertEqual((destination / "private.txt").stat().st_mode & 0o777, 0o600)
            self.assertEqual((destination / "public.txt").stat().st_mode & 0o777, 0o640)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o750)

    @unittest.skipIf(
        os.environ.get("GITHUB_ACTIONS") == "true" and os.geteuid() != 0,
        "requires root-owned chown semantics (VM with nas-state user)",
    )
    def test_restore_to_absent_authority_uses_registry_owned_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            source = root / "source"
            destination = root / "missing-destination"
            source.mkdir()
            (source / "state.db").write_text("payload", encoding="utf-8")
            authority = state.Authority(
                "service-state",
                str(destination),
                sensitive=True,
                owner="service-user",
                group="service-group",
                rootMode="0710",
            )
            fake_user = mock.Mock(pw_uid=1234)
            fake_group = mock.Mock(gr_gid=2345)
            with (
                mock.patch.object(state.pwd, "getpwnam", return_value=fake_user),
                mock.patch.object(state.grp, "getgrnam", return_value=fake_group),
                mock.patch.object(state.os, "chown") as chown,
            ):
                state.restore_path(source, destination, authority)
            self.assertTrue(destination.is_dir())
            self.assertEqual(destination.stat().st_mode & 0o777, 0o710)
            self.assertTrue(any(call.args[1:3] == (1234, 2345) for call in chown.call_args_list))

    def test_quiesce_failure_restarts_units_already_stopped(self) -> None:
        calls: list[tuple[str, str]] = []

        def systemctl(action: str, unit: str, **_kwargs: object) -> mock.Mock:
            calls.append((action, unit))
            if (action, unit) == ("stop", "one.service"):
                raise state.StateError("stop failed")
            return self.completed()

        snapshot = {"one.service": True, "two.service": True}
        with mock.patch.object(state, "run_systemctl", side_effect=systemctl):
            with self.assertRaisesRegex(state.StateError, "stop failed"):
                state.stop_active_units(snapshot)
        self.assertEqual(
            calls,
            [("stop", "two.service"), ("stop", "one.service"), ("start", "two.service")],
        )

    def test_restore_units_honors_generated_profile_list(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"NAS_STATE_RESTORE_UNITS_JSON": '["nas-protected-services.target","NetworkManager.service"]'},
            clear=False,
        ):
            self.assertEqual(
                state.restore_units(),
                ("nas-protected-services.target", "NetworkManager.service"),
            )

    def test_runtime_consumers_are_started_before_reload(self) -> None:
        calls: list[tuple[str, ...]] = []
        active = {"NetworkManager.service": False, "firewalld.service": False}

        def systemctl(*args: str, **_kwargs: object) -> mock.Mock:
            calls.append(tuple(args))
            if args[:2] == ("is-active", "--quiet"):
                unit = args[2]
                return self.completed(0 if active.get(unit, False) else 1)
            if args[0] == "start":
                active[args[1]] = True
            return self.completed()

        snapshot = {
            "nas-protected-services.target": False,
            "NetworkManager.service": True,
            "firewalld.service": True,
        }
        process_calls: list[tuple[str, ...]] = []
        with (
            mock.patch.object(state, "run_systemctl", side_effect=systemctl),
            mock.patch.object(
                state,
                "run_process",
                side_effect=lambda command, **_kwargs: process_calls.append(tuple(command)) or self.completed(),
            ),
        ):
            state.reapply_runtime_consumers(snapshot)

        self.assertLess(calls.index(("start", "NetworkManager.service")), calls.index(("reload", "NetworkManager.service")))
        self.assertLess(calls.index(("start", "firewalld.service")), calls.index(("reload", "firewalld.service")))
        self.assertEqual(process_calls, [("nmcli", "connection", "reload")])

    def test_runtime_consumer_reapply_fails_if_network_profiles_cannot_reload(self) -> None:
        snapshot = {"NetworkManager.service": True}

        def systemctl(*args: str, **_kwargs: object) -> mock.Mock:
            if args[:2] == ("is-active", "--quiet"):
                return self.completed()
            return self.completed()

        with (
            mock.patch.object(state, "run_systemctl", side_effect=systemctl),
            mock.patch.object(state, "run_process", return_value=self.completed(returncode=1)),
        ):
            with self.assertRaisesRegex(state.StateError, "connection profile reload failed"):
                state.reapply_runtime_consumers(snapshot)

    def test_export_refuses_bundle_above_restore_expansion_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            public = root / "public"
            public.write_bytes(b"x" * 4096)
            sensitive = root / "sensitive"
            sensitive.write_text("secret", encoding="utf-8")
            registry = self.registry(public, sensitive, root / "missing")
            with (
                mock.patch.dict(os.environ, self.environment(registry), clear=False),
                mock.patch.object(state, "MAX_ARCHIVE_BYTES", 1024),
            ):
                with self.assertRaisesRegex(state.StateError, "extraction size limit"):
                    state.export_bundle(root / "too-large.tar.gz", include_sensitive=True)
            self.assertFalse((root / "too-large.tar.gz").exists())

    def test_installed_state_registry_fails_closed_when_generated_registry_is_missing(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"NAS_STATE_REGISTRY_FILE": "", "NAS_STATE_REGISTRY_REQUIRED": "1"},
            clear=True,
        ):
            with self.assertRaisesRegex(state.StateError, "required"):
                state.authorities()

    def test_registry_schema_validation_and_duplicate_authorities_fail_closed(self) -> None:
        valid = {
            "name": "ok",
            "source": "/x",
            "kind": "path",
            "sensitive": False,
            "optional": False,
            "restoreStrategy": "path-policy",
            "owner": "root",
            "group": "root",
            "rootMode": "0750",
        }
        invalid_rows = [
            ({"NAS_STATE_REGISTRY_JSON": "not-json"}, "invalid JSON"),
            ({"NAS_STATE_REGISTRY_JSON": "{}"}, "must be an array"),
            ({"NAS_STATE_REGISTRY_JSON": "[1]"}, "must be an object"),
            ({"NAS_STATE_REGISTRY_JSON": json.dumps([{"name": "bad"}])}, "fields must exactly"),
            ({"NAS_STATE_REGISTRY_JSON": json.dumps([{**valid, "name": "BAD"}])}, "name is invalid"),
            ({"NAS_STATE_REGISTRY_JSON": json.dumps([{**valid, "source": ""}])}, "invalid source"),
            ({"NAS_STATE_REGISTRY_JSON": json.dumps([{**valid, "kind": "other"}])}, "invalid kind"),
            ({"NAS_STATE_REGISTRY_JSON": json.dumps([{**valid, "sensitive": "no"}])}, "invalid boolean"),
            ({"NAS_STATE_REGISTRY_JSON": json.dumps([{**valid, "owner": None}])}, "requires an owner"),
            ({"NAS_STATE_REGISTRY_JSON": json.dumps([{**valid, "rootMode": "755"}])}, "invalid root mode"),
            (
                {"NAS_STATE_REGISTRY_JSON": json.dumps([{**valid, "restoreStrategy": "raw-copy"}])},
                "invalid restore strategy",
            ),
        ]
        for environment, message in invalid_rows:
            with self.subTest(message=message), mock.patch.dict(os.environ, environment, clear=True):
                with self.assertRaisesRegex(state.StateError, message):
                    state.authorities()

        row = {**valid, "name": "same"}
        with mock.patch.dict(os.environ, {"NAS_STATE_REGISTRY_JSON": json.dumps([row, row])}, clear=True):
            with self.assertRaisesRegex(state.StateError, "must be unique"):
                state.authorities()

        with tempfile.TemporaryDirectory() as temporary:
            registry = pathlib.Path(temporary) / "registry.json"
            registry.write_text("broken", encoding="utf-8")
            with mock.patch.dict(os.environ, {"NAS_STATE_REGISTRY_FILE": str(registry)}, clear=True):
                with self.assertRaisesRegex(state.StateError, "Invalid state registry file"):
                    state.authorities()

    def test_process_and_database_command_boundaries(self) -> None:
        with mock.patch.object(state, "COMMAND_OUTPUT_LIMIT", 8):
            result = state.run_process(
                [
                    sys.executable,
                    "-c",
                    "import sys; sys.stdout.write('abcdefghijk'); sys.stderr.write('stderr-value')",
                ],
                timeout=4,
            )
        self.assertTrue(result.stdout.endswith("[output truncated]"))
        self.assertTrue(result.stderr.endswith("[output truncated]"))

        with self.assertRaisesRegex(state.StateError, "Command timed out"):
            state.run_process([sys.executable, "-c", "import time; time.sleep(2)"], timeout=0.05)

        with tempfile.TemporaryDirectory() as temporary:
            marker = pathlib.Path(temporary) / "descendant-survived"
            program = (
                "import subprocess,sys,time; "
                "subprocess.Popen([sys.executable,'-c',"
                + repr(
                    "import pathlib,time; time.sleep(0.3); pathlib.Path(" + repr(str(marker)) + ").write_text('bad')"
                )
                + "]); time.sleep(5)"
            )
            with self.assertRaisesRegex(state.StateError, "Command timed out"):
                state.run_process([sys.executable, "-c", program], timeout=0.05)
            __import__("time").sleep(0.5)
            self.assertFalse(marker.exists(), "timed-out subprocess descendant escaped its process group")

        self.assertEqual(
            state.database_command("UNSET_COMMAND", ["tool", "{file}"], "{file}", "/tmp/value"),
            ["tool", "/tmp/value"],
        )
        with mock.patch.dict(os.environ, {"TEST_DATABASE_COMMAND": "not-json"}, clear=True):
            with self.assertRaisesRegex(state.StateError, "JSON command array"):
                state.database_command("TEST_DATABASE_COMMAND", ["x"], "{x}", "value")
        with mock.patch.dict(os.environ, {"TEST_DATABASE_COMMAND": "[]"}, clear=True):
            with self.assertRaisesRegex(state.StateError, "nonempty JSON command array"):
                state.database_command("TEST_DATABASE_COMMAND", ["x"], "{x}", "value")


if __name__ == "__main__":
    unittest.main()
