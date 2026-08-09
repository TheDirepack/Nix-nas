from __future__ import annotations

import json
import pathlib
import stat
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_copyparty_projection as projection  # noqa: E402


class CopypartyProjectionTests(unittest.TestCase):
    def effective(self) -> dict:
        return {
            "storageResources": {
                "projects": {
                    "path": "/tank/projects",
                    "scope": "system",
                    "capabilities": ["read", "write", "move", "delete"],
                },
                "media-library": {
                    "path": "/tank/media",
                    "scope": "system",
                    "capabilities": ["read", "admin"],
                },
            }
        }

    def test_admin_gets_filesystem_root(self) -> None:
        text = projection.render_config(self.effective())
        self.assertIn("[/]\n/\n  accs:\n    A: @nas_admin", text)

    def test_resource_capabilities_map_to_authentik_groups(self) -> None:
        text = projection.render_config(self.effective())
        self.assertIn("[/projects]\n/tank/projects", text)
        self.assertIn("r: @nas_storage_projects_read", text)
        self.assertIn("w: @nas_storage_projects_write", text)
        self.assertIn("m: @nas_storage_projects_move", text)
        self.assertIn("d: @nas_storage_projects_delete", text)
        self.assertIn("r: @nas_storage_media_library_read", text)
        self.assertIn("A: @nas_storage_media_library_admin", text)

    def test_every_projected_resource_retains_admin_recovery_access(self) -> None:
        text = projection.render_config(self.effective())
        self.assertGreaterEqual(text.count("A: @nas_admin"), 3)

    def test_user_scoped_resource_never_exposes_parent_directory(self) -> None:
        effective = self.effective()
        effective["storageResources"]["pi-home"] = {
            "path": "/tank/apps/pi/users",
            "scope": "user",
            "pathTemplate": "/tank/apps/pi/users/{user}",
            "capabilities": ["read", "write", "delete"],
        }
        text = projection.render_config(effective)
        self.assertNotIn("[/pi-home]", text)
        self.assertNotIn("\n/tank/apps/pi/users\n", text)
        self.assertIn("user-scoped resource 'pi-home' intentionally omitted", text)

    def test_user_scoped_resource_requires_identity_template(self) -> None:
        effective = self.effective()
        effective["storageResources"]["broken"] = {
            "path": "/tank/users",
            "scope": "user",
            "capabilities": ["read"],
        }
        with self.assertRaisesRegex(projection.CopypartyProjectionError, "pathTemplate"):
            projection.render_config(effective)

    def test_projection_rejects_unknown_permission(self) -> None:
        effective = self.effective()
        effective["storageResources"]["projects"]["capabilities"].append("execute")
        with self.assertRaisesRegex(projection.CopypartyProjectionError, "unsupported"):
            projection.render_config(effective)

    def test_atomic_projection_writes_readable_include(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            effective_path = root / "effective.json"
            output_path = root / "user.d" / "50-v2-storage.conf"
            effective_path.write_text(json.dumps(self.effective()), encoding="utf-8")
            rendered = projection.reconcile_from_effective(effective_path, output_path)
            self.assertEqual(output_path.read_text(encoding="utf-8"), rendered)
            self.assertEqual(stat.S_IMODE(output_path.stat().st_mode), 0o644)


if __name__ == "__main__":
    unittest.main()
