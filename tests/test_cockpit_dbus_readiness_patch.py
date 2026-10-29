from __future__ import annotations

import asyncio
import errno
import hashlib
import importlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/cockpit-362/dbus-readiness"
PATCH = ROOT / "cockpit/patches/cockpit-dbus-readiness.patch"
NAME = "org.freedesktop.systemd1"
OWNER = ":1.42"


class CockpitDBusReadinessPatchTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        tree = pathlib.Path(temporary.name)
        manifest = json.loads((FIXTURE / "source-manifest.json").read_text())
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

        # Empty package namespaces avoid importing unrelated channels. All
        # lifecycle code and the vendored systemd binding come from the fixture.
        namespaces = {}
        for name, relative in (
            ("cockpit", "src/cockpit"),
            ("cockpit.channels", "src/cockpit/channels"),
            ("cockpit._vendor", "src/cockpit/_vendor"),
        ):
            module = types.ModuleType(name)
            vars(module)["__path__"] = [str(tree / relative)]
            namespaces[name] = module
        modules = mock.patch.dict(sys.modules, namespaces)
        modules.start()
        cls.addClassCleanup(modules.stop)
        cls.native = importlib.import_module("cockpit.channels.dbus")
        cls.channels = importlib.import_module("cockpit.channel")
        cls.routing = importlib.import_module("cockpit.router")

    async def asyncSetUp(self):
        self.bus = mock.Mock(spec=self.native.Bus)
        self.bus.call_method_async = mock.AsyncMock(return_value=(OWNER,))
        self.slot = mock.Mock(spec=["cancel"])
        self.bus.add_match.return_value = self.slot
        for factory in ("default_system", "default_user", "new"):
            patcher = mock.patch.object(self.native.Bus, factory, return_value=self.bus)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.transport = mock.Mock(spec=asyncio.Transport)
        self.router = self.routing.Router([])
        self.router.transport = self.transport
        self.router.transport_control_received("init", {"version": 1, "host": "localhost"})
        self.router.routing_rules.append(self.channels.ChannelRoutingRule(self.router, [self.native.DBusChannel]))

    async def asyncTearDown(self):
        for endpoint in list(self.router.endpoints):
            tasks = list(endpoint._tasks)
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            endpoint.close()

    def open_channel(self, channel="bus", *, name: str | None = NAME, **options):
        message = {"command": "open", "channel": channel, "payload": "dbus-json3", **options}
        if name is not None:
            message["name"] = name
        self.router.channel_control_received(channel, "open", message)
        return self.router.open_channels[channel]

    def frames(self):
        remaining = b"".join(call.args[0] for call in self.transport.write.call_args_list)
        frames = []
        while remaining:
            length, separator, rest = remaining.partition(b"\n")
            self.assertEqual(separator, b"\n")
            size = int(length)
            self.assertGreaterEqual(len(rest), size)
            channel, separator, payload = rest[:size].partition(b"\n")
            self.assertEqual(separator, b"\n")
            frames.append((channel.decode(), json.loads(payload)))
            remaining = rest[size:]
        return frames

    async def finish(self, channel):
        return await asyncio.gather(*list(channel._tasks), return_exceptions=True)

    async def assert_readiness_failure(self, channel, error):
        with self.assertLogs("cockpit.channels.dbus", level="ERROR") as logs:
            results = await self.finish(channel)
            self.assertEqual(
                self.frames(),
                [
                    (
                        "",
                        {
                            "command": "close",
                            "channel": channel.channel,
                            "problem": "internal-error",
                            "message": str(error),
                        },
                    )
                ],
                f"readiness results: {results!r}; routed channels: {list(self.router.open_channels)}",
            )
        self.assertIn(str(error), "\n".join(logs.output))
        self.assertEqual(results, [None])
        self.assertTrue(channel.is_closing())
        self.assertFalse(channel._tasks)
        self.assertNotIn(channel.channel, self.router.open_channels)
        self.assertNotIn(channel, self.router.endpoints)
        self.assertTrue(self.router.no_endpoints.is_set())
        self.assertFalse(self.router._closed)
        self.transport.close.assert_not_called()

    async def test_add_match_einval_closes_frozen_endpoint_with_native_error(self):
        error = OSError(errno.EINVAL, "sd_bus_add_match: Invalid argument")
        self.bus.add_match.side_effect = error
        channel = self.open_channel()
        self.router.channel_data_received("bus", b'{"meta": {"must-not-run": {}}}')
        await self.assert_readiness_failure(channel, error)
        self.assertEqual(channel.cache.cache, {})
        self.bus.add_match.assert_called_once()
        self.bus.call_method_async.assert_not_awaited()

    async def test_owner_query_io_failure_closes_instead_of_leaving_open(self):
        error = OSError(errno.EIO, "sd_bus_call_async: Input/output error")
        self.bus.call_method_async.side_effect = error
        handlers = []

        def add_match(_rule, handler):
            handlers.append(handler)
            return self.slot

        self.bus.add_match.side_effect = add_match
        channel = self.open_channel()

        def cancel():
            self.assertFalse(channel.is_closing())
            handlers.clear()

        self.slot.cancel.side_effect = cancel
        await self.assert_readiness_failure(channel, error)
        self.slot.cancel.assert_called_once_with()
        self.assertEqual(channel.matches, [])
        frames = self.frames()
        signal = mock.Mock(spec=["get_body"])
        signal.get_body.return_value = (NAME, "", OWNER)
        for handler in handlers:
            handler(signal)
        self.assertEqual(self.frames(), frames)
        self.bus.add_match.assert_called_once()
        self.bus.call_method_async.assert_awaited_once_with(
            "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "GetNameOwner", "s", NAME
        )

    async def test_failed_endpoint_does_not_close_another_channel_or_the_bridge(self):
        healthy = self.open_channel("healthy", name=None)
        error = OSError(errno.EINVAL, "sd_bus_add_match: Invalid argument")
        self.bus.add_match.side_effect = error
        failed = self.open_channel("failed")
        with self.assertLogs("cockpit.channels.dbus", level="ERROR"):
            results = await self.finish(failed)
            self.assertEqual(
                self.frames(),
                [
                    ("", {"command": "ready", "channel": "healthy"}),
                    ("", {"command": "close", "channel": "failed", "problem": "internal-error", "message": str(error)}),
                ],
                f"readiness results: {results!r}",
            )
        self.assertEqual(results, [None])
        self.assertEqual(self.router.open_channels, {"healthy": healthy})
        self.assertEqual(self.router.endpoints, {healthy: {"healthy"}})
        self.assertFalse(self.router.no_endpoints.is_set())
        self.assertFalse(healthy.is_closing())
        self.assertFalse(self.router._closed)
        self.transport.close.assert_not_called()

    async def test_failure_uses_existing_task_drain_before_sending_close(self):
        error = OSError(errno.EINVAL, "sd_bus_add_match: Invalid argument")
        self.bus.add_match.side_effect = error
        channel = self.open_channel()
        (readiness,) = channel._tasks
        release = asyncio.Event()
        pending = channel.create_task(release.wait())
        with self.assertLogs("cockpit.channels.dbus", level="ERROR"):
            results = await asyncio.gather(readiness, return_exceptions=True)
            self.assertTrue(channel.is_closing(), f"readiness results: {results!r}")
        self.assertEqual(results, [None])
        self.assertEqual(self.frames(), [])
        self.assertEqual(channel._tasks, {pending})
        self.assertIs(self.router.open_channels["bus"], channel)
        release.set()
        await self.finish(channel)
        self.assertEqual(
            self.frames(),
            [("", {"command": "close", "channel": "bus", "problem": "internal-error", "message": str(error)})],
        )
        self.assertFalse(self.router.endpoints)
        self.assertFalse(self.router.open_channels)

    async def test_success_keeps_owner_ready_and_queued_reply_order(self):
        entered = asyncio.Event()
        release = asyncio.Event()

        async def get_owner(*args):
            entered.set()
            await release.wait()
            return (OWNER,)

        self.bus.call_method_async.side_effect = get_owner
        reply = mock.Mock(spec=["get_body", "get_signature"])
        reply.get_body.return_value = ("native result",)
        reply.get_signature.return_value = "s"
        self.bus.call_async = mock.AsyncMock(return_value=reply)
        channel = self.open_channel()
        self.router.channel_data_received(
            "bus", b'{"call": ["/object", "org.example.Test", "Read", []], "id": "call-1"}'
        )
        await entered.wait()
        self.assertEqual(self.frames(), [])
        self.bus.message_new_method_call.assert_not_called()
        release.set()
        self.assertEqual(await self.finish(channel), [None])
        await self.finish(channel)
        self.assertEqual(
            self.frames(),
            [
                ("bus", {"owner": OWNER}),
                ("", {"command": "ready", "channel": "bus", "unique-name": OWNER}),
                ("bus", {"reply": [["native result"]], "id": "call-1", "flags": None, "type": "s"}),
            ],
        )
        self.assertFalse(channel.is_closing())
        self.assertFalse(channel._tasks)
        self.assertIs(self.router.open_channels["bus"], channel)

    async def test_missing_owner_and_failed_activation_keep_not_found(self):
        self.bus.call_method_async.side_effect = [
            self.native.BusError("org.freedesktop.DBus.Error.NameHasNoOwner", "no owner"),
            self.native.BusError("org.freedesktop.DBus.Error.ServiceUnknown", "not activatable"),
        ]
        channel = self.open_channel()
        self.assertEqual(await self.finish(channel), [None])
        self.assertEqual(
            self.frames(),
            [("bus", {"owner": None}), ("", {"command": "close", "channel": "bus", "problem": "not-found"})],
        )
        self.assertEqual(
            [call.args[3] for call in self.bus.call_method_async.await_args_list],
            ["GetNameOwner", "StartServiceByName"],
        )
        self.assertFalse(self.router.endpoints)

    async def test_activation_signal_keeps_successful_readiness(self):
        async def activate(_destination, _path, _interface, member, *_args):
            if member == "GetNameOwner":
                raise self.native.BusError("org.freedesktop.DBus.Error.NameHasNoOwner", "no owner")
            self.assertEqual(member, "StartServiceByName")
            signal = mock.Mock(spec=["get_body"])
            signal.get_body.return_value = (NAME, "", OWNER)
            self.bus.add_match.call_args.args[1](signal)
            return (1,)

        self.bus.call_method_async.side_effect = activate
        channel = self.open_channel()
        self.assertEqual(await self.finish(channel), [None])
        self.assertEqual(
            self.frames(),
            [("bus", {"owner": OWNER}), ("", {"command": "ready", "channel": "bus", "unique-name": OWNER})],
        )
        self.assertEqual(self.bus.call_method_async.await_count, 2)

    async def test_existing_other_bus_error_keeps_not_found(self):
        self.bus.call_method_async.side_effect = self.native.BusError(
            "org.freedesktop.DBus.Error.AccessDenied", "denied"
        )
        channel = self.open_channel()
        self.assertEqual(await self.finish(channel), [None])
        self.assertEqual(self.frames(), [("", {"command": "close", "channel": "bus", "problem": "not-found"})])
        self.bus.call_method_async.assert_awaited_once()

    async def test_unnamed_channel_keeps_immediate_ready_without_tracking(self):
        channel = self.open_channel(name=None)
        self.assertFalse(channel._tasks)
        self.assertEqual(self.frames(), [("", {"command": "ready", "channel": "bus"})])
        self.bus.add_match.assert_not_called()
        self.bus.call_method_async.assert_not_awaited()

    async def test_existing_ebusy_and_interrupted_match_behavior_is_unchanged(self):
        self.bus.attach_event.side_effect = OSError(errno.EBUSY, "already attached")
        self.bus.add_match.side_effect = [InterruptedError(errno.EINTR, "interrupted"), self.slot]
        channel = self.open_channel()
        self.assertEqual(await self.finish(channel), [None])
        self.assertEqual(self.bus.add_match.call_count, 2)
        self.assertEqual(channel.matches, [self.slot])
        self.assertEqual(self.frames()[-1], ("", {"command": "ready", "channel": "bus", "unique-name": OWNER}))

    async def test_programming_error_still_escapes_without_blanket_task_handler(self):
        error = RuntimeError("unrelated programming defect")
        self.bus.add_match.side_effect = error
        channel = self.open_channel()
        self.assertEqual(await self.finish(channel), [error])
        self.assertFalse(channel.is_closing())
        self.assertEqual(self.frames(), [])
        self.assertIs(self.router.open_channels["bus"], channel)

    def test_running_package_applies_readiness_and_existing_framing_patches(self):
        source = (ROOT / "modules/nas/config/application-services.nix").read_text()
        package = source.split("cockpitPatched = pkgs.cockpit.overrideAttrs", 1)[1].split("  cockpitWebService =", 1)[0]
        self.assertIn("../../../cockpit/patches/cockpit-dbus-readiness.patch", package)
        self.assertIn("../../../cockpit/patches/cockpit-frame-ancestors.patch", package)
        self.assertIn("old.patches or", package)
        self.assertIn("${cockpitPatched}/bin/cockpit-bridge", source)
        self.assertIn("${cockpitPatched}/libexec/cockpit-ws", source)

    def test_development_shell_provides_native_binding_library(self):
        source = (ROOT / "flake.nix").read_text()
        shell = source.split("devShells.x86_64-linux.test =", 1)[1].split("devShells.x86_64-linux.qemu-test =", 1)[0]
        self.assertIn("LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [ pkgs.systemd ];", shell)
