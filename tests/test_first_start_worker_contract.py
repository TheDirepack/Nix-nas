from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_MODULE = ROOT / "modules/nas/default.nix"
WORKER_POLICY = ROOT / "modules/nas/config/first-start-worker.nix"
COCKPIT_API = ROOT / "services/nas_cockpit_api.py"


class FirstStartWorkerContractTests(unittest.TestCase):
    def test_worker_policy_is_loaded(self) -> None:
        default_module = DEFAULT_MODULE.read_text(encoding="utf-8")
        self.assertIn("./config/first-start-worker.nix", default_module)

    def test_transient_worker_gets_required_provisioning_access(self) -> None:
        policy = WORKER_POLICY.read_text(encoding="utf-8")
        self.assertIn("nas-first-start-.service.d/20-setup-access.conf", policy)
        self.assertIn("PrivateDevices=no", policy)
        self.assertIn("ProtectHome=no", policy)
        self.assertIn("ProtectSystem=yes", policy)
        self.assertIn("ReadWritePaths=", policy)

    def test_worker_keeps_non_conflicting_hardening(self) -> None:
        api = COCKPIT_API.read_text(encoding="utf-8")
        self.assertIn('"--property=NoNewPrivileges=yes"', api)
        self.assertIn('"--property=PrivateTmp=yes"', api)


if __name__ == "__main__":
    unittest.main()
