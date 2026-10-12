from __future__ import annotations

import contextlib
import pathlib
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
PATCH = ROOT / "authentik/patches/authentik-blueprint-apply-failure.patch"


class AuthentikBlueprintPatchTests(unittest.TestCase):
    def command(self):
        with tempfile.TemporaryDirectory() as directory:
            tree = pathlib.Path(directory)
            command_path = tree / "authentik/blueprints/management/commands/apply_blueprint.py"
            command_path.parent.mkdir(parents=True)
            shutil.copyfile(ROOT / "tests/fixtures/authentik-apply-blueprint.py.txt", command_path)
            if PATCH.exists():
                subprocess.run(["git", "apply", str(PATCH)], cwd=tree, check=True, capture_output=True)
            source = command_path.read_text()
        self.importer = mock.Mock()
        self.importer.validate.return_value = (True, [])
        self.importer.apply.return_value = True
        self.factory = mock.Mock()
        self.factory.from_string.return_value = self.importer
        self.blueprint = mock.Mock()
        tenant = mock.Mock()
        tenant.objects.filter.return_value = [contextlib.nullcontext()]
        dependencies = {
            "django.core.management.base": types.SimpleNamespace(
                BaseCommand=object, no_translations=lambda method: method
            ),
            "structlog.stdlib": types.SimpleNamespace(get_logger=mock.Mock()),
            "authentik.blueprints.models": types.SimpleNamespace(BlueprintInstance=self.blueprint),
            "authentik.blueprints.v1.importer": types.SimpleNamespace(Importer=self.factory),
            "authentik.tenants.models": types.SimpleNamespace(Tenant=tenant),
        }
        namespace = {}
        with mock.patch.dict(sys.modules, dependencies):
            exec(compile(source, "upstream-apply-blueprint", "exec"), namespace)
        command = namespace["Command"]()
        command.stderr = mock.Mock()
        return command

    def test_apply_failure_exits_nonzero_and_stops_remaining_blueprints(self):
        command = self.command()
        self.importer.apply.return_value = False
        with self.assertRaises(SystemExit) as raised:
            command.handle(blueprints=["failed.yaml", "must-not-apply.yaml"])
        self.assertEqual(raised.exception.code, 1)
        self.importer.apply.assert_called_once_with()
        self.blueprint.assert_called_once_with(path="failed.yaml")
        command.stderr.write.assert_called_once_with("Blueprint failed to apply")

    def test_success_applies_every_blueprint(self):
        command = self.command()
        command.handle(blueprints=["first.yaml", "second.yaml"])
        self.assertEqual(self.importer.apply.call_count, 2)
        command.stderr.write.assert_not_called()

    def test_invalid_blueprint_never_applies(self):
        command = self.command()
        self.importer.validate.return_value = (False, [])
        with self.assertRaises(SystemExit) as raised:
            command.handle(blueprints=["invalid.yaml"])
        self.assertEqual(raised.exception.code, 1)
        self.importer.apply.assert_not_called()
        command.stderr.write.assert_called_once_with("Blueprint invalid")

    def test_apply_exception_remains_fatal(self):
        command = self.command()
        self.importer.apply.side_effect = RuntimeError("database unavailable")
        with self.assertRaisesRegex(RuntimeError, "database unavailable"):
            command.handle(blueprints=["first.yaml", "must-not-apply.yaml"])
        self.blueprint.assert_called_once_with(path="first.yaml")

    def test_canonical_package_installs_the_patch(self):
        source = (ROOT / "modules/nas/internal/account-tools.nix").read_text()
        self.assertIn("../../../authentik/patches/authentik-blueprint-apply-failure.patch", source)
