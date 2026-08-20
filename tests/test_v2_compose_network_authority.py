from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_compose as compose  # noqa: E402


class V2ComposeNetworkAuthorityTests(unittest.TestCase):
    def test_v2_network_policy_rejects_source_declared_ports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            app_root = root / "apps"
            source = app_root / "demo" / "compose.yaml"
            source.parent.mkdir(parents=True)
            source.write_text(
                "services:\n  web:\n    image: example/web\n    ports: ['0.0.0.0:9999:9999']\n",
                encoding="utf-8",
            )
            effective = {"networkProfiles": {}, "storageResources": {}, "credentials": {}}
            service = {
                "name": "Demo",
                "workload": {"kind": "daemon", "activation": "persistent"},
                "runtime": {"type": "compose", "source": str(source)},
                "resources": {"accelerators": []},
                "sandbox": {"mode": "inherit"},
                "storage": [],
                "credentials": [],
                "routes": {},
                "listeners": {},
                "network": {
                    "mode": "isolated",
                    "outboundDefault": "deny",
                    "lanAccess": False,
                    "allowedHostPorts": [],
                    "allowedEgress": [],
                },
            }
            with (
                mock.patch.object(compose, "APP_ROOT", app_root),
                self.assertRaisesRegex(compose.ComposeProjectionError, "V2-owned network fields: ports"),
            ):
                compose.render_compose_override(effective, "demo", service)


if __name__ == "__main__":
    unittest.main()
