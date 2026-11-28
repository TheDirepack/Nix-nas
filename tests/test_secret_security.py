from __future__ import annotations

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
MAINTENANCE_TOOLS = ROOT / "modules/nas/internal/maintenance-tools.nix"


class AlertCredentialTests(unittest.TestCase):
    def test_ntfy_curl_credentials_stay_in_private_config_not_argv(self) -> None:
        source = MAINTENANCE_TOOLS.read_text(encoding="utf-8")
        self.assertIn('curl_config="$(mktemp /run/nas-alert-curl.XXXXXX)"', source)
        self.assertIn('chmod 0600 "$curl_config"', source)
        self.assertIn('user = "admin:$password"', source)
        self.assertNotIn('--user "admin:$password"', source)
        self.assertNotIn('-u "admin:$password"', source)


if __name__ == "__main__":
    unittest.main()
