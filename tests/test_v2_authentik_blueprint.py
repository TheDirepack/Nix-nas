from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_authentik_blueprint as blueprint  # noqa: E402


def effective(*, hostname: bool = False) -> dict:
    exposure = (
        {"type": "hostname", "hostnames": ["demo.example.test", "demo-alt.example.test"], "path": "/ui/"}
        if hostname
        else {"type": "path", "paths": ["/demo/"]}
    )
    return {
        "schemaVersion": 3,
        "services": {"demo": {"enabled": True, "name": "Demo"}},
        "derived": {
            "authorization": {
                "demo": {"capabilities": {"access": "application.demo.access", "admin": "application.demo.admin"}}
            },
            "routes": [
                {
                    "service": "demo",
                    "route": "web",
                    "authMode": "identity",
                    "requiredCapability": "application.demo.access",
                    "exposure": exposure,
                    "portal": {"visible": True, "title": "Demo UI"},
                }
            ],
        },
    }


class V2AuthentikBlueprintTests(unittest.TestCase):
    def test_empty_effective_state_renders_an_empty_entries_list(self) -> None:
        state = {
            "schemaVersion": 3,
            "services": {},
            "derived": {"authorization": {}, "routes": []},
        }
        rendered, manifest = blueprint.render_blueprint(state, public_host="nas.example.test")
        self.assertIn("entries: []\n", rendered.decode())
        self.assertEqual(manifest, {"schemaVersion": 1, "groups": [], "applications": []})

    def test_blueprint_uses_providerless_application_and_group_bindings(self) -> None:
        rendered, manifest = blueprint.render_blueprint(effective(), public_host="nas.example.test")
        text = rendered.decode()
        self.assertIn("model: authentik_core.group", text)
        self.assertIn('name: "application.demo.access"', text)
        self.assertIn('name: "application.demo.admin"', text)
        self.assertIn("model: authentik_core.application", text)
        self.assertIn('slug: "v2-demo-web"', text)
        self.assertIn('meta_launch_url: "https://nas.example.test/demo/"', text)
        self.assertIn("provider: null", text)
        self.assertIn("model: authentik_policies.policybinding", text)
        self.assertIn('group, [name, "application.demo.access"]', text)
        self.assertIn('group, [name, "nas_admin"]', text)
        self.assertNotIn("authentik_providers_proxy", text)
        self.assertNotIn("authentik_outposts", text)
        self.assertEqual(manifest["groups"], ["application.demo.access", "application.demo.admin"])
        self.assertEqual(manifest["applications"], ["v2-demo-web"])

    def test_hostname_route_creates_one_launcher_application_for_route(self) -> None:
        rendered, manifest = blueprint.render_blueprint(effective(hostname=True), public_host="nas.example.test")
        text = rendered.decode()
        self.assertEqual(manifest["applications"], ["v2-demo-web"])
        self.assertIn('meta_launch_url: "https://demo.example.test/ui/"', text)
        self.assertNotIn("demo-alt.example.test", text)

    def test_stale_objects_are_explicitly_removed(self) -> None:
        previous = {
            "schemaVersion": 1,
            "groups": ["application.demo.access", "application.old.access"],
            "applications": ["v2-demo-web", "v2-old-web"],
        }
        rendered, _manifest = blueprint.render_blueprint(effective(), public_host="nas.example.test", previous=previous)
        text = rendered.decode()
        self.assertIn('slug: "v2-old-web"', text)
        self.assertIn('name: "application.old.access"', text)
        old_app = text.index('slug: "v2-old-web"')
        old_group = text.index('name: "application.old.access"')
        self.assertIn("state: absent", text[old_app - 120 : old_app])
        self.assertIn("state: absent", text[old_group - 120 : old_group])

    def test_capability_change_updates_binding_by_target_and_order(self) -> None:
        state = effective()
        state["derived"]["routes"][0]["requiredCapability"] = "application.demo.admin"
        rendered, _manifest = blueprint.render_blueprint(state, public_host="nas.example.test")
        text = rendered.decode()
        target = '!Find [authentik_core.application, [slug, "v2-demo-web"]]'
        self.assertEqual(text.count(target), 2)
        self.assertIn('group: !Find [authentik_core.group, [name, "application.demo.admin"]]', text)
        self.assertIn("order: 0", text)
        self.assertIn("order: 1", text)

    def test_manifest_advances_only_after_explicit_commit(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            effective_path = root / "effective.json"
            output = root / "blueprints" / "nas-managed-services-v2.yaml"
            manifest = root / "objects.json"
            next_manifest = root / "objects.next.json"
            effective_path.write_text(json.dumps(effective()), encoding="utf-8")

            blueprint.generate(
                effective_path=effective_path,
                blueprint_path=output,
                manifest_path=manifest,
                next_manifest_path=next_manifest,
                public_host="nas.example.test",
            )
            self.assertTrue(output.is_file())
            self.assertTrue(next_manifest.is_file())
            self.assertFalse(manifest.exists())

            blueprint.commit_manifest(next_manifest_path=next_manifest, manifest_path=manifest)
            self.assertTrue(manifest.is_file())
            self.assertFalse(next_manifest.exists())
            self.assertEqual(json.loads(manifest.read_text())["applications"], ["v2-demo-web"])

    def test_unsafe_previous_manifest_fails_closed(self) -> None:
        with self.assertRaisesRegex(blueprint.AuthentikBlueprintError, "unsafe identifiers"):
            blueprint.render_blueprint(
                effective(),
                public_host="nas.example.test",
                previous={"schemaVersion": 1, "groups": ["nas_admin"], "applications": []},
            )


if __name__ == "__main__":
    unittest.main()
