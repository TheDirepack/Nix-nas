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
        self.assertIn('systemd.services."nas-first-start-"', policy)
        self.assertIn('overrideStrategy = "asDropin";', policy)
        self.assertIn("PrivateDevices = false;", policy)
        self.assertIn("ProtectHome = true;", policy)
        self.assertIn('ProtectSystem = "yes";', policy)
        # The drop-in must be declared through NixOS systemd unit machinery,
        # not an etc file; explanatory comments may still mention the old
        # mechanism, so assert against executable content only.
        code = "\n".join(line for line in policy.splitlines() if not line.lstrip().startswith("#"))
        self.assertNotIn("environment.etc", code)

    def test_worker_keeps_non_conflicting_hardening(self) -> None:
        api = COCKPIT_API.read_text(encoding="utf-8")
        self.assertIn('"--property=NoNewPrivileges=yes"', api)
        self.assertIn('"--property=PrivateTmp=yes"', api)


if __name__ == "__main__":
    unittest.main()
