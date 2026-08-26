from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SECURE = ROOT / "services/nas_first_start.py"
PIPE_WORKER = ROOT / "services/nas_first_start_pipe.py"
SETUP = ROOT / "services/nas_setup.py"
API = ROOT / "services/nas_first_run_api.py"
BOOTSTRAP = ROOT / "modules/nas/config/bootstrap-security.nix"
PYPROJECT = ROOT / "pyproject.toml"


class SecureFirstStartTests(unittest.TestCase):
    def test_standalone_api_uses_pipe_only_hardened_job_entrypoint(self) -> None:
        module = BOOTSTRAP.read_text(encoding="utf-8")
        api = API.read_text(encoding="utf-8")
        worker = PIPE_WORKER.read_text(encoding="utf-8")
        packaging = PYPROJECT.read_text(encoding="utf-8")
        self.assertIn('nas-first-start-job = "nas_first_start_pipe:main"', packaging)
        self.assertIn('"nas_first_start_pipe"', packaging)
        self.assertIn("NAS_FIRST_START_JOB", module)
        self.assertIn("/bin/nas-first-start-job", module)
        self.assertIn("FIRST_START_JOB", api)
        self.assertIn('"--pipe"', api)
        self.assertIn('"--wait"', api)
        self.assertIn("FIRST_START_SECRET_DELIVERY_TIMEOUT_SECONDS", api)
        self.assertIn("os.set_blocking", api)
        self.assertIn("select.select", api)
        self.assertIn('"--setenv=NAS_SETUP_ALLOW_ROOT=1"', api)
        self.assertNotIn(".password", api)
        self.assertNotIn("--password-file", api)
        self.assertIn("sys.stdin.buffer.read", worker)
        self.assertNotIn("password_file", worker)
        self.assertNotIn("firstStartSetupShim", module)

    def test_public_nas_setup_has_no_legacy_first_run_path(self) -> None:
        packaging = PYPROJECT.read_text(encoding="utf-8")
        setup_source = SETUP.read_text(encoding="utf-8")
        first_start_source = SECURE.read_text(encoding="utf-8")
        self.assertIn('nas-setup = "nas_setup:main"', packaging)
        self.assertNotIn("nas_setup_dispatch", packaging)
        self.assertFalse((ROOT / "services/nas_setup_dispatch.py").exists())
        self.assertNotIn("def _first_run_locked(", setup_source)
        self.assertNotIn("def first_run(", setup_source)
        self.assertNotIn("run-first-start-job", setup_source)
        self.assertNotIn("def run_first_start_job(", first_start_source)
        self.assertNotIn("--password-file", first_start_source)

    def test_permanent_password_never_opens_bootstrap_kdbx(self) -> None:
        source = SECURE.read_text(encoding="utf-8")
        bootstrap_block = source[
            source.index("def bootstrap_authority_ready") : source.index("def permanent_runtime_ready")
        ]
        self.assertNotIn("keepassxc", bootstrap_block.lower())
        self.assertNotIn("password =", bootstrap_block)
        self.assertIn("NAS.kdbx", bootstrap_block)
        self.assertIn("kdbx-password", bootstrap_block)
        self.assertLess(source.index('"permanent-runtime-selection"'), source.index('"permanent-keepass-database"'))
        self.assertLess(source.index('"permanent-keepass-database"'), source.index('"permanent-secret-initialization"'))

    def test_bootstrap_authority_and_private_markers_reject_group_world_access(self) -> None:
        source = SECURE.read_text(encoding="utf-8")
        root_file = source[source.index("def _regular_root_file") : source.index("def _read_private_root_json")]
        private_json = source[
            source.index("def _read_private_root_json") : source.index("def bootstrap_authority_ready")
        ]
        self.assertIn("& 0o077", root_file)
        self.assertIn("& 0o077", private_json)
        self.assertNotIn("& 0o022", root_file)
        self.assertNotIn("& 0o022", private_json)

    def test_no_bootstrap_secret_promotion_stage_exists(self) -> None:
        source = SECURE.read_text(encoding="utf-8")
        self.assertNotIn("promote_bootstrap", source)
        self.assertNotIn('"bootstrap-secret-promotion"', source)
        self.assertNotIn("bootstrap-secret-initialization", source)
        self.assertNotIn("bootstrap-keepass-database", source)
        self.assertIn("bootstrap-authority-ready", source)

    def test_bootstrap_retirement_is_after_permanent_verification_and_before_completion(self) -> None:
        source = SECURE.read_text(encoding="utf-8")
        verification = source.index('"permanent-control-plane-verification"')
        setup_app = source.index('"setup-application-retirement"')
        authority = source.index('"bootstrap-authority-retirement"')
        account = source.index('"bootstrap-account-retirement"')
        final_state = source.index('"final-state"')
        complete = source.index("journal.complete(report)")
        self.assertLess(verification, setup_app)
        self.assertLess(setup_app, authority)
        self.assertLess(authority, account)
        self.assertLess(account, final_state)
        self.assertLess(final_state, complete)

    def test_requested_service_work_finishes_before_bootstrap_is_destroyed(self) -> None:
        source = SECURE.read_text(encoding="utf-8")
        retirement = source.index('"setup-application-retirement"')
        for stage in ('"share-directories"', '"managed-services-policy"', '"verification"'):
            with self.subTest(stage=stage):
                self.assertLess(source.index(stage), retirement)
        self.assertLess(source.index("if preflight_ran:"), retirement)

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
        self.assertIn('"--property=ProtectSystem=strict"', api)
        self.assertIn('"--property=ProtectHome=read-only"', api)
        self.assertIn("/etc /home", api)
        self.assertNotIn('"--property=PrivateDevices=yes"', api)


if __name__ == "__main__":
    unittest.main()
