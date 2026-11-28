from __future__ import annotations

import pathlib
import unittest

from repo_test_utils import keepass_sources

ROOT = pathlib.Path(__file__).resolve().parents[1]
ACTIVATE = (ROOT / "go/internal/nassecrets/activate.go").read_text(encoding="utf-8")


class V2SecretLifecycleTests(unittest.TestCase):
    """Static boundaries of activation; behaviour is in test_nas_secrets_blackbox."""

    def test_secret_activation_remains_keepass_backed_and_transactional(self) -> None:
        for needle in (
            "a.unlock(ctx, src)",
            "keepass.AuthentikSecretKey",
            "txn.Begin(",
            "staged.Swap(ctx)",
            "swapped.Commit(ctx)",
        ):
            self.assertIn(needle, ACTIVATE)

    def test_secret_activation_validates_platform_substrate_not_copyparty(self) -> None:
        self.assertIn("identityUnits       = []syspath.Unit{unitAuthentik, unitAuthentikWorker, unitCaddy}", ACTIVATE)
        self.assertNotIn("copyparty", ACTIVATE)
        self.assertIn('v2SystemdState = "/run/nas-control/systemd-reconciled.json";', keepass_sources())
        self.assertIn('StartUnits    []string        `json:"startUnits"`', ACTIVATE)

    def test_discarded_generation_helpers_do_not_return(self) -> None:
        source = keepass_sources()
        for name in (
            "nas-secret-stage-copyparty",
            "nas-secret-stage-authentik",
            "nas-keepass-validate",
            "nas-secret-fault-test",
        ):
            self.assertNotIn(name, source)

    def test_authentik_token_check_accepts_retired_bootstrap_authority(self) -> None:
        self.assertIn("Authentik bootstrap token is retired", keepass_sources())


if __name__ == "__main__":
    unittest.main()
