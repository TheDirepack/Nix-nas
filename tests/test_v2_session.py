from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import types
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_session as session  # noqa: E402


class V2SessionRuntimeTests(unittest.TestCase):
    def descriptor(self, root: pathlib.Path, *, user_scoped: bool = False) -> pathlib.Path:
        storage = root / ("users" if user_scoped else "instances")
        storage.mkdir()
        path = root / "session.json"
        token = "{user}" if user_scoped else "{instance}"
        path.write_text(
            json.dumps(
                {
                    "schemaVersion": 2,
                    "serviceId": "code-agent",
                    "podman": "/usr/bin/podman",
                    "systemctl": "/usr/bin/systemctl",
                    "systemdRun": "/usr/bin/systemd-run",
                    "python": "/usr/bin/python3",
                    "runner": "/opt/nas/nas_v2_session.py",
                    "targetUnit": "nas-v2-session-code-agent.target",
                    "requires": ["nas-v2-session-code-agent.target", "nas-v2-snet-code-agent-network.service"],
                    "after": ["nas-v2-session-code-agent.target", "nas-v2-snet-code-agent-network.service"],
                    "requiresUser": user_scoped,
                    "image": "example.invalid/agent:1",
                    "command": ["agent", "serve"],
                    "runArgs": ["--pull=missing", "--network=none"],
                    "volumeTemplates": [
                        {
                            "root": str(storage),
                            "sourceTemplate": str(storage / token),
                            "target": "/workspace",
                            "access": "rw",
                            "scope": "user" if user_scoped else "instance",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        return path

    def test_instance_volume_substitution_stays_shell_free(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            descriptor_path = self.descriptor(root)
            descriptor = session._load_descriptor(descriptor_path)
            run, _stop, _cleanup = session._podman_commands(descriptor, "work-01", None)
            self.assertEqual(run[0:2], ["/usr/bin/podman", "run"])
            self.assertIn("nas-v2-session-code-agent-work-01", run)
            self.assertIn(f"{root / 'instances/work-01'}:/workspace:rw", run)
            self.assertEqual(run[-3:], ["example.invalid/agent:1", "agent", "serve"])

    def test_user_scoped_volume_requires_and_substitutes_authenticated_user(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            descriptor_path = self.descriptor(root, user_scoped=True)
            descriptor = session._load_descriptor(descriptor_path)
            with self.assertRaisesRegex(session.SessionError, "requires --user"):
                session._podman_commands(descriptor, "work-01", None)
            run, _stop, _cleanup = session._podman_commands(descriptor, "work-01", "alice@example.com")
            self.assertIn(f"{root / 'users/alice@example.com'}:/workspace:rw", run)
            self.assertIn("io.nixos-nas.v2.user=alice@example.com", run)
            self.assertNotIn("alice@example.com", session.unit_name("code-agent", "work-01", "alice@example.com"))

    def test_volume_template_access_and_scope_must_be_strings(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            descriptor_path = self.descriptor(root)
            document = json.loads(descriptor_path.read_text(encoding="utf-8"))
            template = document["volumeTemplates"][0]
            for field, value in (("access", None), ("access", 1), ("scope", None), ("scope", ["instance"])):
                with self.subTest(field=field, value=value):
                    mutated = json.loads(json.dumps(document))
                    mutated["volumeTemplates"][0][field] = value
                    descriptor_path.write_text(json.dumps(mutated), encoding="utf-8")
                    with self.assertRaisesRegex(session.SessionError, "volume template fields are invalid"):
                        session._load_descriptor(descriptor_path)
            self.assertEqual(template["access"], "rw")
            self.assertEqual(template["scope"], "instance")

    def test_instance_identifier_rejects_systemd_and_path_metacharacters(self):
        for value in ("../escape", "bad/name", "name@unit", "UPPER", "x y", ""):
            with self.subTest(value=value), self.assertRaises(session.SessionError):
                session.validate_instance_id(value)

    def test_user_identifier_rejects_path_metacharacters(self):
        for value in ("../escape", "bad/name", "x y", "", ".."):
            with self.subTest(value=value), self.assertRaises(session.SessionError):
                session.validate_user_id(value)

    def test_existing_symlink_cannot_escape_instance_storage_root(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            descriptor_path = self.descriptor(root)
            outside = root / "outside"
            outside.mkdir()
            (root / "instances" / "escape").symlink_to(outside, target_is_directory=True)
            descriptor = session._load_descriptor(descriptor_path)
            with self.assertRaisesRegex(session.SessionError, "escapes its declared storage root"):
                session._resolved_volume_args(descriptor, "escape", None)

    def test_transient_start_carries_dependencies_and_user_without_database(self):
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            descriptor_path = self.descriptor(root, user_scoped=True)
            captured: list[list[str]] = []
            original = session._run
            session._run = lambda command, timeout=None: captured.append(command) or types.SimpleNamespace(returncode=0)
            try:
                self.assertEqual(session.start_transient(descriptor_path, "abc1", "alice"), 0)
            finally:
                session._run = original
            command = captured[0]
            self.assertEqual("/usr/bin/systemd-run", command[0])
            self.assertIn("--collect", command)
            self.assertIn("--service-type=exec", command)
            self.assertIn("--property=PartOf=nas-v2-session-code-agent.target", command)
            self.assertTrue(any(item.startswith("--property=Requires=") for item in command))
            self.assertEqual(command[-2:], ["--user", "alice"])
            self.assertFalse(any("session.db" in item for item in command))

    def test_descriptor_path_is_derived_from_safe_service_id(self):
        root = pathlib.Path("/run/test-projection")
        self.assertEqual(root / "descriptors/code-agent.session.json", session.descriptor_path("code-agent", root))
        with self.assertRaises(session.SessionError):
            session.descriptor_path("../escape", root)


if __name__ == "__main__":
    unittest.main()
