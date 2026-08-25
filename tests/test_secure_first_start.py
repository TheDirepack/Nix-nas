from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SECURE = ROOT / "services/nas_first_start.py"
API = ROOT / "services/nas_first_run_api.py"
BOOTSTRAP = ROOT / "modules/nas/config/bootstrap-security.nix"
PYPROJECT = ROOT / "pyproject.toml"


class SecureFirstStartTests(unittest.TestCase):
    def test_standalone_api_uses_dedicated_hardened_job_entrypoint(self) -> None:
        module = BOOTSTRAP.read_text(encoding="utf-8")
        api = API.read_text(encoding="utf-8")
        packaging = PYPROJECT.read_text(encoding="utf-8")
        self.assertIn('nas-first-start-job = "nas_first_start:main"', packaging)
        self.assertIn('"nas_first_start"', packaging)
        self.assertIn("NAS_FIRST_START_JOB", module)
        self.assertIn("/bin/nas-first-start-job", module)
        self.assertIn("FIRST_START_JOB", api)
        self.assertIn('"--setenv=NAS_SETUP_ALLOW_ROOT=1"', api)
        self.assertNotIn("firstStartSetupShim", module)

    def test_permanent_password_never_opens_bootstrap_kdbx(self) -> None:
        source = SECURE.read_text(encoding="utf-8")
        bootstrap_block = source[source.index("def bootstrap_authority_ready"):source.index("def permanent_runtime_ready")]
        self.assertNotIn("keepassxc", bootstrap_block.lower())
        self.assertNotIn("password =", bootstrap_block)
        self.assertIn("NAS.kdbx", bootstrap_block)
        self.assertIn("kdbx-password", bootstrap_block)
        self.assertIn("selecting a fresh root-hosted permanent trust domain", source)
        self.assertLess(source.index("permanent-runtime-selection"), source.index("permanent-keepass-database"))
        self.assertLess(source.index("permanent-keepass-database"), source.index("permanent-secret-initialization"))

    def test_no_bootstrap_secret_promotion_stage_exists(self) -> None:
        source = SECURE.read_text(encoding="utf-8")
        self.assertNotIn("promote", source.lower())
        self.assertNotIn("bootstrap-secret-initialization", source)
        self.assertNotIn("bootstrap-keepass-database", source)
        self.assertIn("bootstrap-authority-ready", source)

    def test_bootstrap_retirement_precedes_completion_state(self) -> None:
        source = SECURE.read_text(encoding="utf-8")
        retirement = source.index('"bootstrap-account-retirement"')
        final_state = source.index('"final-state"')
        complete = source.index("journal.complete(report)")
        self.assertLess(retirement, final_state)
        self.assertLess(final_state, complete)

    def test_permanent_machine_secrets_are_generated_after_fresh_kdbx(self) -> None:
        source = SECURE.read_text(encoding="utf-8")
        database = source.index('"permanent-keepass-database"')
        secrets = source.index('"permanent-secret-initialization"')
        storage = source.index('"storage"', secrets)
        self.assertLess(database, secrets)
        self.assertLess(secrets, storage)
        self.assertIn('["nas-secrets", "init"]', source)

    def test_privileged_job_sandbox_matches_first_run_mutations(self) -> None:
        api = API.read_text(encoding="utf-8")
        self.assertIn('"--property=NoNewPrivileges=no"', api)
        self.assertIn('"--property=ProtectHome=read-only"', api)
        self.assertIn("/etc /home", api)
        self.assertNotIn('"--property=PrivateDevices=yes"', api)


if __name__ == "__main__":
    unittest.main()
