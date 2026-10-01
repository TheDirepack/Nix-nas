from __future__ import annotations

import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "release-inventory.py"
SPEC = importlib.util.spec_from_file_location("release_inventory", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inventory)


class ReleaseInventoryTests(unittest.TestCase):
    def test_closure_entries_accept_mapping_and_list_shapes(self) -> None:
        mapping = {
            "/nix/store/b": {"narHash": "sha256-b", "narSize": 2, "references": ["/nix/store/a"]},
            "/nix/store/a": {"narHash": "sha256-a", "narSize": 1, "references": []},
        }
        self.assertEqual([entry["path"] for entry in inventory._closure_entries(mapping)], ["/nix/store/a", "/nix/store/b"])
        listed = [{"path": "/nix/store/a", "narHash": "sha256-a"}]
        self.assertEqual(inventory._closure_entries(listed)[0]["narHash"], "sha256-a")

    def test_image_pin_inventory_is_sorted_and_keeps_empty_digest_slots(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            (root / "z-image.nix").write_text(
                '{\n  repository = "example/z";\n  tag = "2";\n  digests = {\n    x86_64_linux = "sha256:z";\n  };\n}\n',
                encoding="utf-8",
            )
            (root / "a-image.nix").write_text(
                '{\n  repository = "example/a";\n  tag = "1";\n  digests = {\n    aarch64_linux = "";\n    x86_64_linux = "sha256:a";\n  };\n}\n',
                encoding="utf-8",
            )
            pins = inventory.collect_oci_pins(root)
            self.assertEqual([pin["file"] for pin in pins], ["a-image.nix", "z-image.nix"])
            self.assertEqual(pins[0]["digests"]["aarch64_linux"], "")
            self.assertEqual(pins[0]["repository"], "example/a")

    def test_build_inventory_combines_closure_and_image_pins(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            fake_nix = root / "fake-nix"
            payload = {"/nix/store/system": {"narHash": "sha256-system", "narSize": 42, "references": []}}
            fake_nix.write_text(
                "#!/bin/sh\nprintf '%s\\n' '" + json.dumps(payload).replace("'", "'\\''") + "'\n",
                encoding="utf-8",
            )
            fake_nix.chmod(0o755)
            (root / "demo-image.nix").write_text(
                '{ repository = "example/demo";\n  tag = "3";\n  digests = { x86_64_linux = "sha256:demo"; };\n}\n',
                encoding="utf-8",
            )
            result = inventory.build_inventory(
                root=root,
                system_path="/nix/store/system",
                nix_bin=str(fake_nix),
                revision="deadbeef",
            )
            self.assertEqual(result["schemaVersion"], 1)
            self.assertEqual(result["sourceRevision"], "deadbeef")
            self.assertEqual(result["nixClosure"][0]["path"], "/nix/store/system")
            self.assertEqual(result["ociImages"][0]["repository"], "example/demo")


if __name__ == "__main__":
    unittest.main()
