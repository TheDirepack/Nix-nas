from __future__ import annotations

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class V2SecretLifecycleTests(unittest.TestCase):
    def test_secret_activation_remains_keepass_backed_and_transactional(self) -> None:
        source = (ROOT / "modules/nas/internal/secret-tools.nix").read_text(encoding="utf-8")
        activate = source.split("command_activate() (", 1)[1].split("command_status() {", 1)[0]

        self.assertIn("prompt_unlock", activate)
        self.assertIn("get_secret authentik-secret-key", activate)
        self.assertIn("nas_secret_tx_swap", activate)
        self.assertIn("nas_secret_tx_commit", activate)
        self.assertIn("kp_args() {", source)
        self.assertIn("get_secret() {", source)

    def test_discarded_generation_helpers_do_not_return(self) -> None:
        source = (ROOT / "modules/nas/internal/secret-tools.nix").read_text(encoding="utf-8")

        self.assertNotIn("nas-secret-stage-copyparty", source)
        self.assertNotIn("nas-secret-stage-authentik", source)
        self.assertNotIn("nas-keepass-validate", source)
        self.assertNotIn("nas-secret-fault-test", source)


if __name__ == "__main__":
    unittest.main()
