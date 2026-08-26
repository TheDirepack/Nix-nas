from __future__ import annotations

import importlib
import sys
import unittest
from unittest import mock

from repo_test_utils import ROOT, text

SERVICES = ROOT / "services"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))


class SecurityReauditContracts(unittest.TestCase):
    def test_setup_job_capability_is_deleted_from_caddy_access_logs(self) -> None:
        caddy = text("modules/nas/config/caddy-bootstrap.nix")
        api = text("services/nas_first_run_api.py")
        self.assertIn('JOB_TOKEN_HEADER = "X-NAS-Setup-Job-Token"', api)
        self.assertIn("format filter {", caddy)
        self.assertIn("request>headers>X-NAS-Setup-Job-Token delete", caddy)
        self.assertIn("wrap json", caddy)

    def test_packaged_cockpit_cli_refuses_obsolete_first_run_ingress(self) -> None:
        pyproject = text("pyproject.toml")
        entry = text("services/nas_cockpit_entry.py")
        self.assertIn('nas-cockpit-api = "nas_cockpit_entry:main"', pyproject)
        self.assertIn('frozenset({"first-start", "first-start-job-status", "serve"})', entry)
        self.assertIn("legacy first-run ingress is disabled", entry)

        module = importlib.import_module("nas_cockpit_entry")
        for command in ("first-start", "first-start-job-status", "serve"):
            with self.subTest(command=command), mock.patch.object(sys, "argv", ["nas-cockpit-api", command]):
                with mock.patch.object(module.nas_cockpit_api, "main") as legacy:
                    self.assertEqual(module.main(), 2)
                    legacy.assert_not_called()

    def test_cockpit_ui_never_collects_first_run_human_credentials(self) -> None:
        frontend_api = text("cockpit/src/api.js")
        setup_page = text("cockpit/src/pages/setup-page.jsx")
        self.assertNotIn("startFirstRun", frontend_api)
        self.assertNotIn("KeePassXC database password", setup_page)
        self.assertNotIn("Administrator password", setup_page)
        self.assertNotIn("first-start-job-status", setup_page)
        self.assertIn('href="/setup/"', setup_page)
        self.assertIn("Cockpit does not collect or persist those", setup_page)

    def test_kdbx_shared_mode_requires_dedicated_administrator_group(self) -> None:
        preflight = text("modules/nas/config/secret-file-preflight.nix")
        secrets = text("modules/nas/internal/secret-tools.nix")
        self.assertIn('"permanent KDBX" 0660 admin nas-administrators', preflight)
        self.assertIn('"KeePassXC database" nas-administrators', secrets)
        self.assertIn('expected_gid="$(getent group "$shared_group"', secrets)
        self.assertIn("permissions & ~8#660", secrets)
        self.assertIn("permissions & 8#007", secrets)
        self.assertIn('"KeePassXC key file"', secrets)

    def test_coding_agent_namespace_cannot_pivot_into_host_or_private_lans(self) -> None:
        default = text("modules/ai/default.nix")
        network = text("modules/ai/coding-agent-network-security.nix")
        self.assertIn("./coding-agent-network-security.nix", default)
        self.assertIn("NAS_PI_INPUT", network)
        self.assertIn("NAS_PI_FORWARD", network)
        self.assertIn("-d ${piHostVethIp}/32 -p udp --dport 53 -j ACCEPT", network)
        self.assertIn("-d ${piHostVethIp}/32 -p tcp --dport ${toString ai.llamaSwap.port} -j ACCEPT", network)
        self.assertIn("${iptables} -A ${inputChain} -j REJECT", network)
        for private_range in (
            "10.0.0.0/8",
            "100.64.0.0/10",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "224.0.0.0/4",
        ):
            self.assertIn(private_range, network)
        self.assertIn("--ctstate ESTABLISHED,RELATED -j ACCEPT", network)
        self.assertNotIn("-C FORWARD -s ${piNsVethIp}/30 -j ACCEPT", network)
        self.assertNotIn("-C FORWARD -d ${piNsVethIp}/30 -j ACCEPT", network)


if __name__ == "__main__":
    unittest.main()
