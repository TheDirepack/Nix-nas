from __future__ import annotations

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class V2SecretLifecycleTests(unittest.TestCase):
    def test_secret_activation_does_not_require_v2_application_runtime(self) -> None:
        source = (ROOT / "modules/nas/internal/secret-tools.nix").read_text(encoding="utf-8")
        activate = source.split("command_activate() {", 1)[1].split("command_recover() {", 1)[0]

        self.assertIn("authentik.service authentik-worker.service caddy.service", activate)
        self.assertNotIn("copyparty.service", activate)
        self.assertNotIn("/run/copyparty/http.sock", activate)

    def test_copyparty_credentials_are_still_staged_independently_of_lifecycle(self) -> None:
        source = (ROOT / "modules/nas/internal/secret-tools.nix").read_text(encoding="utf-8")
        self.assertIn("nas-secret-stage-copyparty", source)
        self.assertIn('[[ -s "$stage/copyparty/admin-password" ]]', source)


if __name__ == "__main__":
    unittest.main()
