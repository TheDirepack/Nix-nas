from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_session as session  # noqa: E402


class V2SessionRuntimeTests(unittest.TestCase):
    def test_instance_volume_substitution_stays_shell_free(self):
        self.assertEqual("nas-v2-session-code-agent-work-01", session.container_name("code-agent", "work-01"))

    def test_user_scoped_volume_requires_and_substitutes_authenticated_user(self):
        self.assertNotIn("alice@example.com", session.unit_name("code-agent", "work-01", "alice@example.com"))

    def test_instance_identifier_rejects_systemd_and_path_metacharacters(self):
        for value in ("../escape", "bad/name", "name@unit", "UPPER", "x y", ""):
            with self.subTest(value=value), self.assertRaises(session.SessionError):
                session.validate_instance_id(value)

    def test_user_identifier_rejects_path_metacharacters(self):
        for value in ("../escape", "bad/name", "x y", "", ".."):
            with self.subTest(value=value), self.assertRaises(session.SessionError):
                session.validate_user_id(value)

    def test_descriptor_path_is_derived_from_safe_service_id(self):
        root = pathlib.Path("/run/test-projection")
        self.assertEqual(root / "descriptors/code-agent.session.json", session.descriptor_path("code-agent", root))
        with self.assertRaises(session.SessionError):
            session.descriptor_path("../escape", root)


if __name__ == "__main__":
    unittest.main()
