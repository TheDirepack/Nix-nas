from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import textwrap
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
NAS_SECRETS = ROOT / "zig/src/nas_secrets.zig"
sys.path.insert(0, str(ROOT / "tests"))

from test_nas_secrets import PASSWORD, SECRET_ROOT, Appliance  # noqa: E402


class V2SecretLifecycleTests(unittest.TestCase):
    def test_stop_revokes_readiness_before_systemd_can_reactivate_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            nas = Appliance(pathlib.Path(raw))
            root = nas.path(SECRET_ROOT)
            root.mkdir(parents=True)
            (root / "ready").touch()
            (root / "credential").touch()
            # The stop must observe the ready marker already gone and the credential still present.
            guard = nas.bin / "systemctl"
            guard.write_text(
                textwrap.dedent(
                    f"""\
                    #!/bin/sh
                    [ ! -e {root}/ready ] || exit 91
                    [ -e {root}/credential ] || exit 92
                    exit 0
                    """
                ),
                encoding="utf-8",
            )
            result = nas.run("stop", stdin="")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(root.exists())

    def test_secret_activation_remains_keepass_backed_and_transactional(self) -> None:
        source = NAS_SECRETS.read_text(encoding="utf-8")
        activate = source[source.index("fn commandActivate(") : source.index("fn finishRollback(")]
        self.assertIn("app.promptUnlock()", activate)
        self.assertIn("transaction.init(&ctx", activate)
        self.assertIn("staged.swap()", activate)
        self.assertIn("swapped.commit()", activate)
        self.assertIn('db.get(.@"authentik-secret-key")', source)

    def test_secret_activation_validates_platform_substrate_not_copyparty(self) -> None:
        source = NAS_SECRETS.read_text(encoding="utf-8")
        self.assertIn(
            'const failed_units = [_]UnitName{ UnitName.lit("authentik.service"), UnitName.lit("authentik-worker.service"), UnitName.lit("caddy.service") };',
            source,
        )
        self.assertNotIn("copyparty", source)
        self.assertIn(
            'v2_systemd_state: []const u8 = "/run/nas-control/systemd-reconciled.json"',
            (ROOT / "zig/src/config.zig").read_text(),
        )
        self.assertIn("startUnits", source)

    def test_discarded_generation_helpers_do_not_return(self) -> None:
        sources = (ROOT / "modules/nas/internal/secret-tools.nix").read_text(encoding="utf-8") + NAS_SECRETS.read_text()
        for name in (
            "nas-secret-stage-copyparty",
            "nas-secret-stage-authentik",
            "nas-keepass-validate",
            "nas-secret-fault-test",
        ):
            self.assertNotIn(name, sources)

    def test_authentik_token_check_accepts_retired_bootstrap_authority(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            nas = Appliance(pathlib.Path(raw))
            nas.initialise()
            reused = nas.run("check-authentik-token")
            self.assertEqual(reused.returncode, 1)
            self.assertIn("still the bootstrap token", reused.stderr)
            data = json.loads(nas.db.read_text(encoding="utf-8"))
            del data["entries"]["NAS/authentik-bootstrap-token"]
            nas.db.write_text(json.dumps(data), encoding="utf-8")
            retired = nas.run("check-authentik-token")
            self.assertEqual(retired.returncode, 0, retired.stderr)
            self.assertIn("Authentik bootstrap token is retired", retired.stdout)
            self.assertNotIn(PASSWORD, retired.stdout + retired.stderr)


if __name__ == "__main__":
    unittest.main()
