from __future__ import annotations

import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_source_watch as source_watch  # noqa: E402
import nas_v2_systemd_reconcile as reconcile  # noqa: E402


class V2SourceWatchTests(unittest.TestCase):
    def test_path_value_preserves_literal_characters_and_escapes_specifiers(self):
        value = '/managed/source with spaces %n "quoted" \\literal.yaml'
        self.assertEqual(source_watch._path_value(value), value.replace("%", "%%"))

    def test_path_value_rejects_unit_directive_injection(self):
        for character in ("\x00", "\r", "\n"):
            with self.subTest(character=character), self.assertRaises(source_watch.SourceWatchProjectionError):
                source_watch._path_value(f"/managed/source{character}Unit=other.service")

    def test_path_value_rejects_endings_systemd_cannot_preserve(self):
        for ending in (" ", "\t", "\\"):
            with self.subTest(ending=ending), self.assertRaises(source_watch.SourceWatchProjectionError):
                source_watch._path_value(f"/managed/source{ending}")

    @unittest.skipUnless(shutil.which("systemd-analyze"), "systemd-analyze is not installed")
    def test_generated_source_watch_is_accepted_by_real_systemd(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = root / 'source with spaces 100% "quoted" \\literal.yaml'
            source.write_text("services: {}\n")
            watch = root / "nas-v2-source-demo.path"
            watch.write_bytes(source_watch._path_unit("demo", [source]))
            target = root / "nas-managed-services-reconcile.service"
            true_bin = shutil.which("true")
            self.assertIsNotNone(true_bin)
            target.write_text(f"[Service]\nType=oneshot\nExecStart={true_bin}\n")
            result = subprocess.run(
                ["systemd-analyze", "verify", str(watch), str(target)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def manifest(self) -> dict:
        return {
            "schemaVersion": 1,
            "links": [],
            "quadletLinks": [],
            "ownedUnits": [],
            "startUnits": [],
            "stopUnits": [],
            "fingerprints": {},
        }

    def test_managed_enabled_compose_source_is_watched(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            app_root = root / "apps"
            service_root = app_root / "demo"
            service_root.mkdir(parents=True)
            source = service_root / "compose.yaml"
            source.write_text("services: {web: {image: test}}\n", encoding="utf-8")
            effective = {
                "services": {
                    "demo": {
                        "managed": True,
                        "enabled": True,
                        "runtime": {"type": "compose", "source": str(source)},
                    }
                }
            }
            files: dict[pathlib.Path, bytes] = {}
            manifest = self.manifest()
            output = root / "projection"
            with mock.patch.object(source_watch, "APP_ROOT", app_root):
                source_watch.augment_projection(effective, output_dir=output, files=files, manifest=manifest)

        unit_name = "nas-v2-source-demo.path"
        unit = files[output / "units" / unit_name].decode()
        self.assertIn(f"PathChanged={source.resolve()}\n", unit)
        self.assertIn("Unit=nas-managed-services-reconcile.service", unit)
        self.assertIn(unit_name, manifest["ownedUnits"])
        self.assertIn(unit_name, manifest["startUnits"])
        self.assertNotIn(unit_name, manifest["stopUnits"])

    def test_managed_disabled_compose_source_is_not_watched(self):
        effective = {
            "services": {
                "demo": {
                    "managed": True,
                    "enabled": False,
                    "runtime": {"type": "compose", "source": "/var/lib/nas-control/apps/demo/compose.yaml"},
                }
            }
        }
        files: dict[pathlib.Path, bytes] = {}
        manifest = self.manifest()
        source_watch.augment_projection(
            effective,
            output_dir=pathlib.Path("/run/nas-control/systemd"),
            files=files,
            manifest=manifest,
        )
        self.assertEqual(files, {})
        self.assertEqual(manifest["ownedUnits"], [])
        self.assertEqual(manifest["startUnits"], [])

    def test_unmanaged_source_does_not_get_v2_watch(self):
        effective = {
            "services": {
                "demo": {
                    "managed": False,
                    "runtime": {"type": "compose", "source": "/var/lib/nas-control/apps/demo/compose.yaml"},
                }
            }
        }
        files: dict[pathlib.Path, bytes] = {}
        manifest = self.manifest()
        source_watch.augment_projection(
            effective,
            output_dir=pathlib.Path("/run/nas-control/systemd"),
            files=files,
            manifest=manifest,
        )
        self.assertEqual(files, {})
        self.assertEqual(manifest["ownedUnits"], [])
        self.assertEqual(manifest["startUnits"], [])

    def test_python_requirements_file_is_a_managed_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            app_root = root / "apps"
            service_root = app_root / "demo"
            service_root.mkdir(parents=True)
            requirements = service_root / "requirements.lock"
            requirements.write_text("example==1\n", encoding="utf-8")
            service = {
                "managed": True,
                "runtime": {
                    "type": "python",
                    "dependencies": {"requirementsFile": str(requirements)},
                },
            }
            with mock.patch.object(source_watch, "APP_ROOT", app_root):
                self.assertEqual(
                    source_watch.source_paths({}, "demo", service),
                    [requirements.resolve()],
                )

    def test_managed_source_symlink_retargeted_release_keeps_stable_watch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            app_root = root / "apps"
            service_root = app_root / "demo"
            releases = service_root / "releases"
            releases.mkdir(parents=True)
            first = releases / "one.yaml"
            second = releases / "two.yaml"
            first.write_text("services: {}\n", encoding="utf-8")
            second.write_text("services: {web: {}}\n", encoding="utf-8")
            configured = service_root / "compose.yaml"
            configured.symlink_to(first.relative_to(service_root))
            effective = {
                "services": {
                    "demo": {
                        "managed": True,
                        "enabled": True,
                        "runtime": {"type": "compose", "source": str(configured)},
                    }
                }
            }

            def projected_unit():
                files = {}
                with mock.patch.object(source_watch, "APP_ROOT", app_root):
                    paths = source_watch.source_paths({}, "demo", effective["services"]["demo"])
                    self.assertEqual(paths, [configured])
                    source_watch.augment_projection(
                        effective,
                        output_dir=root / "projection",
                        files=files,
                        manifest=self.manifest(),
                    )
                return files[root / "projection/units/nas-v2-source-demo.path"].decode()

            before = projected_unit()
            self.assertIn(f"PathChanged={configured}\n", before)
            self.assertIn(f"PathChanged={service_root}\n", before)
            self.assertNotIn(f"PathChanged={first}\n", before)

            replacement = service_root / ".compose.next"
            replacement.symlink_to(second.relative_to(service_root))
            replacement.replace(configured)
            after = projected_unit()
            self.assertEqual(before, after, "watch definition must survive release selector retargeting")
            self.assertEqual(configured.resolve(), second)

    def test_intermediate_symlink_watches_link_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            app_root = root / "apps"
            service_root = app_root / "demo"
            release = service_root / "releases" / "v1"
            release.mkdir(parents=True)
            (release / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
            current = service_root / "current"
            current.symlink_to(release.relative_to(service_root), target_is_directory=True)
            configured = current / "compose.yaml"
            effective = {
                "services": {
                    "demo": {
                        "managed": True,
                        "enabled": True,
                        "runtime": {"type": "compose", "source": str(configured)},
                    }
                }
            }
            files = {}
            with mock.patch.object(source_watch, "APP_ROOT", app_root):
                source_watch.augment_projection(
                    effective,
                    output_dir=root / "projection",
                    files=files,
                    manifest=self.manifest(),
                )
            unit = files[root / "projection/units/nas-v2-source-demo.path"].decode()
            self.assertIn(f"PathChanged={configured}\n", unit)
            self.assertIn(f"PathChanged={service_root}\n", unit)

    def test_source_symlink_escape_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            app_root = root / "apps"
            service_root = app_root / "demo"
            service_root.mkdir(parents=True)
            outside = root / "outside.yaml"
            outside.write_text("services: {}\n", encoding="utf-8")
            source = service_root / "compose.yaml"
            source.symlink_to(outside)
            service = {
                "managed": True,
                "runtime": {"type": "compose", "source": str(source)},
            }
            with (
                mock.patch.object(source_watch, "APP_ROOT", app_root),
                self.assertRaisesRegex(source_watch.SourceWatchProjectionError, "managed app root"),
            ):
                source_watch.source_paths({}, "demo", service)

    def test_target_chain_symlink_parents_remain_watched_after_atomic_retarget(self):
        for absolute_target in (False, True):
            with self.subTest(absolute_target=absolute_target), tempfile.TemporaryDirectory() as tmp:
                root = pathlib.Path(tmp)
                app_root = root / "apps"
                service_root = app_root / "demo"
                releases = service_root / "releases"
                for version in ("one", "two"):
                    release = releases / version
                    release.mkdir(parents=True)
                    (release / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
                current = releases / "current"
                current.symlink_to("one", target_is_directory=True)
                configured = service_root / "compose.yaml"
                target = current / "compose.yaml"
                configured.symlink_to(target if absolute_target else target.relative_to(service_root))
                effective = {
                    "services": {
                        "demo": {
                            "managed": True,
                            "runtime": {"type": "compose", "source": str(configured)},
                        }
                    }
                }

                def projected_paths():
                    files = {}
                    with mock.patch.object(source_watch, "APP_ROOT", app_root):
                        source_watch.augment_projection(
                            effective,
                            output_dir=root / "projection",
                            files=files,
                            manifest=self.manifest(),
                        )
                    unit = files[root / "projection/units/nas-v2-source-demo.path"].decode()
                    return [
                        line.removeprefix("PathChanged=")
                        for line in unit.splitlines()
                        if line.startswith("PathChanged=")
                    ]

                before = projected_paths()
                # Removing the intermediate symlink's parent (/demo/releases)
                # from the watch set makes this assertion fail.
                self.assertEqual(set(before), {str(configured), str(service_root), str(releases)})
                self.assertEqual(len(before), 3)
                self.assertNotEqual({str(configured), str(service_root)}, set(before))
                replacement = releases / ".current-next"
                replacement.symlink_to("two", target_is_directory=True)
                replacement.replace(current)
                self.assertEqual(configured.resolve(strict=True), releases / "two/compose.yaml")
                self.assertEqual(projected_paths(), before)

    def test_distinct_file_symlink_hops_watch_each_parent_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            app_root = pathlib.Path(tmp) / "apps"
            service_root = app_root / "demo"
            source = service_root / "source/compose.yaml"
            source.parent.mkdir(parents=True)
            source.write_text("services: {}\n", encoding="utf-8")
            middle = service_root / "selectors/current.yaml"
            middle.parent.mkdir()
            middle.symlink_to("../source/compose.yaml")
            configured = service_root / "compose.yaml"
            configured.symlink_to("selectors/current.yaml")
            with mock.patch.object(source_watch, "APP_ROOT", app_root):
                self.assertEqual(
                    source_watch._symlink_parent_paths("demo", [configured, configured]),
                    sorted([service_root, middle.parent], key=str),
                )

    def test_symlink_loop_terminates_on_visited_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            app_root = pathlib.Path(tmp) / "apps"
            service_root = app_root / "demo"
            service_root.mkdir(parents=True)
            first = service_root / "first"
            second = service_root / "second"
            first.symlink_to("second")
            second.symlink_to("first")
            with mock.patch.object(source_watch, "APP_ROOT", app_root):
                self.assertEqual(source_watch._symlink_parent_paths("demo", [first]), [service_root])

    def test_native_systemd_validation_failure_is_fatal(self):
        files = {
            pathlib.Path("/projection/units/nas-v2-source-demo.path"): b"[Path]\nPathChanged=/tmp/demo\n",
        }
        with tempfile.TemporaryDirectory() as tmp:
            validator = pathlib.Path(tmp) / "systemd-analyze"
            validator.write_text("#!/bin/sh\nexit 9\n", encoding="utf-8")
            validator.chmod(validator.stat().st_mode | stat.S_IXUSR)
            with self.assertRaisesRegex(source_watch.SourceWatchProjectionError, "rejected"):
                source_watch.validate_source_watches(files, systemd_analyze_bin=str(validator))

    def test_validate_passes_recursive_errors_to_systemd_analyze(self):
        with mock.patch.object(source_watch.subprocess, "run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
            files = {
                pathlib.Path("/projection/units/nas-v2-source-demo.path"): b"[Path]\nPathChanged=/tmp/demo\n",
            }
            source_watch.validate_source_watches(files, systemd_analyze_bin="/bin/systemd-analyze")
            args = mock_run.call_args.args[0]
            self.assertEqual(args[0], "/bin/systemd-analyze")
            self.assertEqual(args[1], "verify")
            self.assertIn("--recursive-errors=one", args)

    def test_reconciler_safe_target_accepts_path_units(self):
        target, affected = reconcile._safe_target(
            pathlib.Path("/run/systemd/system"),
            "nas-v2-source-demo.path",
        )
        self.assertEqual(target, pathlib.Path("/run/systemd/system/nas-v2-source-demo.path"))
        self.assertEqual(affected, "nas-v2-source-demo.path")


if __name__ == "__main__":
    unittest.main()
