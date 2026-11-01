from __future__ import annotations

import os
import pathlib
import shutil
import tempfile
import unittest
from unittest import mock

import nas_v2_source_watch as source_watch


class SourceWatchValidationTests(unittest.TestCase):
    def test_no_watches_does_not_invoke_the_validator(self) -> None:
        with mock.patch.object(source_watch.subprocess, "run") as run:
            source_watch.validate_source_watches(
                {pathlib.Path("/projection/units/example.service"): b"[Service]\n"},
                systemd_analyze_bin="unused-validator",
            )
        run.assert_not_called()


@unittest.skipUnless(shutil.which("systemd-analyze"), "systemd-analyze is not installed")
class NativeSourceWatchValidationTests(unittest.TestCase):
    def validate(self, *, warning: bool = False, required: bool = False, missing: bool = False) -> None:
        with tempfile.TemporaryDirectory() as raw:
            lookup = pathlib.Path(raw) / "installed-units"
            lookup.mkdir()
            true_bin = shutil.which("true")
            self.assertIsNotNone(true_bin)
            service = f"[Service]\nType=oneshot\nExecStart={true_bin}\n"
            (lookup / "nas-managed-services-reconcile.service").write_text(service)
            dependency = "nas-source-watch-fixture-required.service"
            if required and not missing:
                (lookup / dependency).write_text(service)
            content = source_watch._path_unit("demo", [pathlib.Path('/fixture/source with spaces 100% "quoted".yaml')])
            if required:
                content = content.replace(b"[Unit]\n", f"[Unit]\nRequires={dependency}\n".encode())
            if warning:
                content = content.replace(b"[Path]\n", b"[Path]\nUnknownSourceWatchKey=yes\n")
            with mock.patch.dict(os.environ, {"SYSTEMD_UNIT_PATH": str(lookup) + ":"}):
                source_watch.validate_source_watches(
                    {pathlib.Path("/projection/units/nas-v2-source-demo.path"): content},
                    systemd_analyze_bin="systemd-analyze",
                )

    def test_generated_watch_with_installed_reconcile_service_is_valid(self) -> None:
        self.validate()

    def test_unknown_key_in_a_generated_watch_is_fatal(self) -> None:
        with self.assertRaisesRegex(source_watch.SourceWatchProjectionError, "UnknownSourceWatchKey"):
            self.validate(warning=True)

    def test_required_dependency_is_found_in_the_normal_unit_search_path(self) -> None:
        self.validate(required=True)

    def test_missing_required_dependency_is_still_fatal(self) -> None:
        with self.assertRaisesRegex(
            source_watch.SourceWatchProjectionError, "nas-source-watch-fixture-required.service"
        ):
            self.validate(required=True, missing=True)
