from __future__ import annotations

import errno
import hashlib
import importlib.util
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/cockpit-362"
PATCH = ROOT / "cockpit/patches/cockpit-default-bus-cache.patch"


class CockpitDefaultBusPatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        tree = pathlib.Path(temporary.name)
        manifest = json.loads((FIXTURE / "default-bus-cache.json").read_text())
        for row in manifest["files"]:
            source = FIXTURE / row["fixture"]
            raw = source.read_bytes()
            assert hashlib.sha256(raw).hexdigest() == row["sha256"], row["fixture"]
            assert hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == row["gitBlob"]
            target = tree / row["target"]
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        if PATCH.exists():
            subprocess.run(["git", "apply", str(PATCH)], cwd=tree, check=True, capture_output=True)
        package = tree / "vendor/systemd_ctypes/src/systemd_ctypes"
        modules = mock.patch.dict(sys.modules)
        modules.start()
        cls.addClassCleanup(modules.stop)
        spec = importlib.util.spec_from_file_location(
            "_cockpit_systemd_fixture", package / "__init__.py", submodule_search_locations=[str(package)]
        )
        assert spec is not None and spec.loader is not None
        cls.binding = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cls.binding
        spec.loader.exec_module(cls.binding)

    def setUp(self):
        self.openers = {}
        for scope in ("system", "user"):
            cache = f"_default_{scope}_instance"
            self.assertIsNone(getattr(self.binding.Bus, cache))
            self.addCleanup(setattr, self.binding.Bus, cache, None)
            patcher = mock.patch.object(self.binding.Bus, f"_default_{scope}", side_effect=self.allocate)
            self.openers[scope] = patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch.object(self.binding.Bus, "attach_event", autospec=True)
        self.attach = patcher.start()
        self.addCleanup(patcher.stop)

    def allocate(self, destination):
        # sd_bus_new allocates a local handle only. Native default-bus opens and
        # event attachment stay mocked; no address, connection or start is used.
        self.binding.Bus._new(destination)

    def factory(self, scope: str, *, attach_event: bool = True):
        return getattr(self.binding.Bus, f"default_{scope}")(attach_event=attach_event)

    def cached(self, scope: str):
        return getattr(self.binding.Bus, f"_default_{scope}_instance")

    def assert_open_failure_is_not_cached(self, scope: str):
        error = OSError(errno.ENOENT, f"sd_bus_default_{scope}: No such file or directory")
        opener = self.openers[scope]
        opener.side_effect = error
        with self.assertRaises(OSError) as raised:
            self.factory(scope)
        self.assertIs(raised.exception, error)
        opener.assert_called_once()
        self.attach.assert_not_called()
        self.assertIsNone(self.cached(scope), "failed native open must not publish a null bus")

        opener.side_effect = self.allocate
        bus = self.factory(scope)
        self.assertIsNotNone(bus.value)
        self.assertIs(self.cached(scope), bus)
        self.assertEqual(opener.call_count, 2)
        self.attach.assert_called_once_with(bus, None, 0)
        self.assertIs(self.factory(scope), bus)
        self.assertEqual(opener.call_count, 2)

    def assert_attach_failure_is_not_cached(self, scope: str):
        error = OSError(errno.EINVAL, "sd_bus_attach_event: Invalid argument")
        self.attach.side_effect = error
        with self.assertRaises(OSError) as raised:
            self.factory(scope)
        self.assertIs(raised.exception, error)
        self.openers[scope].assert_called_once()
        self.assertEqual(self.attach.call_count, 1)
        self.assertIsNone(self.cached(scope), "failed attachment must not publish an incompletely initialized bus")

        self.attach.side_effect = None
        bus = self.factory(scope)
        self.assertIsNotNone(bus.value)
        self.assertIs(self.cached(scope), bus)
        self.assertEqual(self.openers[scope].call_count, 2)
        self.assertEqual(self.attach.call_count, 2)
        self.attach.assert_called_with(bus, None, 0)
        self.assertIs(self.factory(scope), bus)
        self.assertEqual(self.attach.call_count, 2)

    def assert_success_is_cached_once(self, scope: str):
        bus = self.factory(scope)
        self.assertIsNotNone(bus.value)
        self.assertIs(self.cached(scope), bus)
        self.assertIs(self.factory(scope), bus)
        self.openers[scope].assert_called_once()
        self.attach.assert_called_once_with(bus, None, 0)

    def assert_manual_attachment_behavior_is_preserved(self, scope: str):
        bus = self.factory(scope, attach_event=False)
        self.assertIsNotNone(bus.value)
        self.assertIs(self.cached(scope), bus)
        self.assertIs(self.factory(scope, attach_event=False), bus)
        self.assertIs(self.factory(scope, attach_event=True), bus)
        self.openers[scope].assert_called_once()
        self.attach.assert_not_called()

    def test_failed_system_open_does_not_cache_a_null_bus(self):
        self.assert_open_failure_is_not_cached("system")

    def test_failed_user_open_does_not_cache_a_null_bus(self):
        self.assert_open_failure_is_not_cached("user")

    def test_failed_system_attachment_does_not_cache_an_incomplete_bus(self):
        self.assert_attach_failure_is_not_cached("system")

    def test_failed_user_attachment_does_not_cache_an_incomplete_bus(self):
        self.assert_attach_failure_is_not_cached("user")

    def test_successful_system_bus_is_cached_once(self):
        self.assert_success_is_cached_once("system")

    def test_successful_user_bus_is_cached_once(self):
        self.assert_success_is_cached_once("user")

    def test_system_manual_attachment_behavior_is_preserved(self):
        self.assert_manual_attachment_behavior_is_preserved("system")

    def test_user_manual_attachment_behavior_is_preserved(self):
        self.assert_manual_attachment_behavior_is_preserved("user")

    def test_failed_system_open_does_not_invalidate_the_healthy_user_cache(self):
        healthy = self.factory("user")
        error = OSError(errno.ENOENT, "sd_bus_default_system: No such file or directory")
        self.openers["system"].side_effect = error
        with self.assertRaises(OSError) as raised:
            self.factory("system")
        self.assertIs(raised.exception, error)
        self.assertIs(self.factory("user"), healthy)
        self.assertIs(self.cached("user"), healthy)
        self.openers["user"].assert_called_once()
        self.openers["system"].assert_called_once()
        self.attach.assert_called_once_with(healthy, None, 0)
        self.assertIsNone(self.cached("system"))

    def test_running_package_applies_vendor_and_existing_framing_patches(self):
        source = (ROOT / "modules/nas/config/application-services.nix").read_text()
        package = source.split("cockpitPatched = pkgs.cockpit.overrideAttrs", 1)[1].split("  cockpitWebService =", 1)[0]
        self.assertIn("../../../cockpit/patches/cockpit-default-bus-cache.patch", package)
        self.assertIn("../../../cockpit/patches/cockpit-frame-ancestors.patch", package)
        self.assertIn("old.patches or", package)
        self.assertIn("if err.errno not in (errno.EBUSY, errno.EINVAL):", package)
        self.assertIn("${cockpitPatched}/bin/cockpit-bridge", source)

    def test_development_shell_provides_native_binding_library(self):
        source = (ROOT / "flake.nix").read_text()
        shell = source.split("devShells.x86_64-linux.test =", 1)[1].split("devShells.x86_64-linux.qemu-test =", 1)[0]
        self.assertIn("LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [ pkgs.systemd ];", shell)
