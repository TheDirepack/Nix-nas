from __future__ import annotations

import base64
import hashlib
import http.server
import json
import os
import re
import shutil
import socketserver
import threading
import subprocess
import tempfile
import unittest
from pathlib import Path

from repo_test_utils import ROOT, text


class ContractTests(unittest.TestCase):
    def test_update_script_keeps_git_integrity_checks_but_not_path_ownership_policy(self):
        updater = text("scripts/update-nas.sh")
        cockpit = text("services/nas_cockpit_api.py")
        self.assertIn("git_safe", updater)
        self.assertIn("--ff-only", updater)
        self.assertNotIn("check_tree_ownership", updater)
        self.assertNotIn("Unexpected symlink", updater)
        self.assertNotIn("''${", updater)
        self.assertIn("${BASH_REMATCH[1]}", updater)
        self.assertIn('nas-update", "--status", "--json', cockpit)

    def test_searchable_docs_include_all_management_surfaces_and_sources(self):
        tools = text("modules/nas/internal/documentation-tools.nix")
        summary = text("docs/src/SUMMARY.md")
        self.assertIn("--help-flags", tools)
        self.assertIn("authentik-nas-user-settings-blueprint.md", tools)
        self.assertIn("nix-options-source.md", tools)
        self.assertIn("installed-versions.md", tools)
        self.assertIn("cockpit-source.md", tools)
        self.assertIn("modules/nas/config/observability.nix", tools)
        self.assertIn("services/nas_identity_sync.py", tools)
        self.assertIn("services/nas_setup.py", tools)
        self.assertIn("project-CHANGELOG.md", tools)
        self.assertNotIn("REVIEW-ALPHA", tools)
        self.assertNotIn("project-ALPHA-", summary)
        self.assertIn("Locked-state unlock", summary)
        self.assertIn("Web interfaces and endpoints", summary)
        self.assertIn("Trusted superusers", summary)

    def test_packaging_concerns_are_split_without_duplicate_exports(self):
        accounts = text("modules/nas/internal/account-tools.nix")
        documentation = text("modules/nas/internal/documentation-tools.nix")
        internal = text("modules/nas/internal/default.nix")
        self.assertNotIn("nasDocumentation =", accounts)
        self.assertIn("nasDocumentation =", documentation)
        self.assertIn("documentation_tools = import ./documentation-tools.nix", internal)
        self.assertIn('mergeChecked "account and documentation tools"', internal)
        self.assertNotIn("storage-tools.nix", documentation)
        self.assertIn("zfs-tools.nix", documentation)

    def test_ci_runs_tests_and_pins_actions(self):
        workflow = text(".github/workflows/ci.yml")
        self.assertIn("./scripts/run-unit-tests.py", workflow)
        uses = re.findall(r"^\s*-?\s*uses:\s*([^\s#]+)", workflow, flags=re.MULTILINE)
        self.assertTrue(uses)
        self.assertTrue(all(re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", item) for item in uses))
        self.assertNotIn("web/settings", workflow)
        self.assertNotIn("web/portal/*.js", workflow)
        self.assertIn("./scripts/preflight.sh", workflow)
        self.assertIn("ruff check services tests scripts", workflow)
        self.assertIn("pyright --project pyproject.toml", workflow)
        self.assertIn("--coverage coverage.json --quiet", workflow)
        self.assertIn('select = ["E4", "E7", "E9", "F"]', text("pyproject.toml"))
        self.assertIn('typeCheckingMode = "basic"', text("pyproject.toml"))
        self.assertFalse((ROOT / "ruff.toml").exists())
        self.assertFalse((ROOT / "pyrightconfig.json").exists())

    def test_release_packaging_verifies_exact_staged_content(self):
        packaging = text("scripts/package-release.sh")
        self.assertIn("unsafe archive member", packaging)
        self.assertIn("archive file set does not exactly match staged release", packaging)
        self.assertIn("archive manifest mismatch", packaging)
        self.assertIn("sha256sum -c MANIFEST.sha256", packaging)
        self.assertIn("NAS_PREFLIGHT_VERIFY_MANIFEST=1", packaging)
        self.assertIn("release checkout is dirty or has untracked files", packaging)
        self.assertIn("release input contains a symlink", packaging)
        self.assertIn("release input contains a non-regular object", packaging)
        self.assertIn("provenance.json", packaging)
        self.assertIn('mv "$publish_tmp" "$publish_final"', packaging)

    def test_release_artifact_naming_is_clean_and_version_preserving(self):
        packaging = text("scripts/package-release.sh")
        naming = text("docs/development/artifact-naming.md")
        self.assertIn('artifact_name="Nix OS NAS $display_version"', packaging)
        self.assertIn('artifact_name+=" source"', packaging)
        self.assertIn('archive_root="nixos-nas-$version"', packaging)
        version = text("VERSION").strip()
        match = re.fullmatch(r"(\d+)\.(\d+)\.0-alpha\.(\d+)", version)
        self.assertIsNotNone(match)
        assert match is not None
        display = f"{match.group(1)}.{match.group(2)}.{match.group(3)}"
        self.assertIn(f"Nix OS NAS {display} source.zip", naming)
        self.assertIn("Documentation-only changes do not require a version bump", naming)
        self.assertIn("Every code change requires a new version number", naming)
        self.assertIn("packaging-script change is a code change", naming)

    def test_release_artifact_name_rejects_control_whitespace(self):
        with tempfile.TemporaryDirectory() as temporary:
            for bad in ("Nix\tOS NAS 2.2.5 source", "Nix\nOS NAS 2.2.5 source"):
                with self.subTest(name=repr(bad)):
                    result = subprocess.run(
                        ["bash", "scripts/package-release.sh", "--source-only", "--name", bad, temporary],
                        cwd=ROOT,
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    self.assertIn("Invalid artifact name", result.stderr)

    def test_curl_config_encoder_preserves_unicode_without_control_characters(self):
        script = text("scripts/live-validation.sh")
        prefix = script.split('case "${1:-}" in', 1)[0]
        value = 'Unicode ✓ Ü quote" slash\\ colon:#='
        command = prefix + '\nprintf \'%s\' "$(curl_config_escape "$1")"\n'
        result = subprocess.run(
            ["bash", "-c", command, "bash", value],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Unicode ✓ Ü", result.stdout)
        self.assertIn('\\"', result.stdout)
        self.assertIn("\\\\", result.stdout)

    def test_complete_release_provenance_hashes_the_actual_staged_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            stage = temporary_path / "stage" / "nixos-nas-test"
            (stage / "cockpit" / "dist").mkdir(parents=True)
            (stage / "release-evidence" / "qemu").mkdir(parents=True)
            (stage / "release-evidence" / "installer").mkdir(parents=True)
            fixtures = {
                "cockpit/package-lock.json": b"lock",
                "cockpit/dist/build-meta.json": b"build",
                "release-evidence/qemu/commit.txt": b"qemu-commit",
                "release-evidence/qemu/checks.txt": b"qemu-checks",
                "release-evidence/installer/commit.txt": b"installer-commit",
                "release-evidence/installer/checks.txt": b"installer-checks",
            }
            for relative, content in fixtures.items():
                target = stage / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
            status = temporary_path / "preflight.json"
            status.write_text('{"result":"passed","incompleteChecks":[]}\n', encoding="utf-8")
            out = temporary_path / "provenance.json"
            result = subprocess.run(
                [
                    "python3",
                    "scripts/lib/release_provenance.py",
                    "--out",
                    str(out),
                    "--version",
                    "2.2.0-alpha.5",
                    "--artifact-name",
                    "Nix OS NAS 2.2.5 release",
                    "--archive-root",
                    "nixos-nas-test",
                    "--validation",
                    "complete",
                    "--archive-hash",
                    "a" * 64,
                    "--manifest-hash",
                    "b" * 64,
                    "--flake-hash",
                    "c" * 64,
                    "--commit",
                    "d" * 40,
                    "--selection-policy",
                    "git-tracked-clean",
                    "--status",
                    str(status),
                    "--stage-root",
                    str(stage),
                    "--git-tree",
                    "e" * 40,
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            provenance = json.loads(out.read_text(encoding="utf-8"))
            self.assertFalse(provenance["sourceOnly"])
            self.assertEqual(
                provenance["cockpitPackageLockSha256"],
                hashlib.sha256(fixtures["cockpit/package-lock.json"]).hexdigest(),
            )
            self.assertEqual(
                provenance["cockpitBuildMetaSha256"],
                hashlib.sha256(fixtures["cockpit/dist/build-meta.json"]).hexdigest(),
            )
            evidence = provenance["evidence"]
            self.assertEqual(
                evidence["qemuCommitSha256"], hashlib.sha256(fixtures["release-evidence/qemu/commit.txt"]).hexdigest()
            )
            self.assertEqual(
                evidence["qemuChecksSha256"], hashlib.sha256(fixtures["release-evidence/qemu/checks.txt"]).hexdigest()
            )
            self.assertEqual(
                evidence["installerCommitSha256"],
                hashlib.sha256(fixtures["release-evidence/installer/commit.txt"]).hexdigest(),
            )
            self.assertEqual(
                evidence["installerChecksSha256"],
                hashlib.sha256(fixtures["release-evidence/installer/checks.txt"]).hexdigest(),
            )

    def test_live_validation_curl_helpers_round_trip_special_credentials(self):
        received: list[str | None] = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 - stdlib callback name
                received.append(self.headers.get("Authorization"))
                self.send_response(204)
                self.end_headers()

            def log_message(self, *_args):
                pass

        with socketserver.TCPServer(("127.0.0.1", 0), Handler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                script = text("scripts/live-validation.sh")
                prefix = script.split('case "${1:-}" in', 1)[0]
                url = f"http://127.0.0.1:{server.server_address[1]}/"
                username = 'user " space:#=+_-.,@!$%^&*()[]{}\\tail'
                password = 'pa"ss \\ :#=+_-.,@!$%^&*()[]{}'
                command = prefix + '\ncurl_basic "$1" "$2" --silent --show-error --output /dev/null "$3"\n'
                result = subprocess.run(
                    ["bash", "-c", command, "bash", username, password, url],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                expected_basic = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()
                self.assertEqual(received.pop(0), expected_basic)

                token = 'abc"def \\ :#=token'
                command = prefix + '\ncurl_bearer "$1" --silent --show-error --output /dev/null "$2"\n'
                result = subprocess.run(
                    ["bash", "-c", command, "bash", token, url],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(received.pop(0), f"Bearer {token}")

                unicode_value = "snowman-☃-check-✓"
                command = prefix + '\ncurl_config_escape "$1"\n'
                result = subprocess.run(
                    ["bash", "-c", command, "bash", unicode_value],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(result.stdout, unicode_value)
            finally:
                server.shutdown()
                thread.join(timeout=5)

    def test_source_archive_consumer_preserves_executable_modes(self):
        workflow = text(".github/workflows/ci.yml")
        packaging = text("scripts/package-release.sh")
        self.assertIn('unzip -q "$archive" -d "$extract"', workflow)
        self.assertIn("archive mode mismatch", packaging)
        self.assertIn("archived_mode", packaging)
        self.assertIn("staged_mode", packaging)
        package_step = workflow.split("      - name: Package and verify as an untrusted consumer", 1)[1]
        self.assertIn('mv cockpit/node_modules "$dependencies"', package_step)
        self.assertIn('mv "$dependencies" cockpit/node_modules', package_step)
        self.assertIn('extract="$RUNNER_TEMP/extracted-source"', package_step)
        self.assertIn("Restore verified source archive", workflow)
        self.assertIn("source-archive-${{ github.sha }}", workflow)
        self.assertIn("Verify restored source archive", workflow)
        restore_source = workflow.index("Restore verified source archive")
        package_source = workflow.index("Package and verify as an untrusted consumer")
        save_source = workflow.index("Save verified source archive")
        self.assertLess(restore_source, package_source)
        self.assertLess(package_source, save_source)
        self.assertLess(
            package_step.index('mv cockpit/node_modules "$dependencies"'), package_step.index("package-release.sh")
        )

    def test_pipeline_summary_checks_out_its_behavioral_policy(self):
        workflow = text(".github/workflows/ci.yml")
        summary = workflow.split("  summary:\n", 1)[1]
        self.assertIn("actions/checkout@", summary)
        self.assertIn("python3 scripts/ci-summary.py", summary)

    def test_release_packaging_rejects_ignored_secrets_links_and_fifos(self):
        scenarios = (
            ("ignored secret", lambda root: root / "secrets" / "leak.txt"),
            ("symlink", lambda root: root / "external-link"),
            ("fifo", lambda root: root / "release-input.fifo"),
        )
        for label, target_factory in scenarios:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "source"
                shutil.copytree(
                    ROOT,
                    root,
                    ignore=shutil.ignore_patterns(
                        ".pytest_cache",
                        ".ruff_cache",
                        "__pycache__",
                        ".coverage",
                        ".coverage.*",
                        "coverage.json",
                        "node_modules",
                        "state",
                    ),
                )
                shutil.rmtree(root / ".git", ignore_errors=True)
                if label == "ignored secret":
                    # A non-git tree is authorized by the allowlist shipped inside a
                    # source archive; seed it from the pristine copy so the injected
                    # file is an unreviewed extra against that authority.
                    subprocess.run(
                        [
                            "python3",
                            str(root / "scripts" / "lib" / "manifest.py"),
                            "--root",
                            str(root),
                            "--out",
                            str(root / "MANIFEST.sha256"),
                        ],
                        check=True,
                        capture_output=True,
                    )
                target = target_factory(root)
                if label == "ignored secret":
                    target.parent.mkdir(parents=True)
                    target.write_text("do-not-publish", encoding="utf-8")
                    expected = "unreviewed files"
                elif label == "symlink":
                    outside = Path(temporary) / "outside.txt"
                    outside.write_text("external-data", encoding="utf-8")
                    target.symlink_to(outside)
                    expected = "contains a symlink"
                else:
                    os.mkfifo(target)
                    expected = "contains a non-regular object"
                environment = os.environ.copy()
                environment["NAS_PREFLIGHT_SKIP_TESTS"] = "1"
                environment["NAS_PREFLIGHT_SKIP_FUZZ"] = "1"
                result = subprocess.run(
                    ["bash", "scripts/package-release.sh", "--source-only", str(Path(temporary) / "out")],
                    cwd=root,
                    env=environment,
                    capture_output=True,
                    text=True,
                    timeout=45,
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stdout + result.stderr)

    def test_release_packaging_records_linked_worktree_git_provenance(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repository"
            linked = Path(temporary) / "linked"
            shutil.copytree(
                ROOT,
                repository,
                ignore=shutil.ignore_patterns(
                    ".git",
                    ".pytest_cache",
                    ".ruff_cache",
                    "__pycache__",
                    ".coverage",
                    ".coverage.*",
                    "coverage.json",
                    "node_modules",
                    "state",
                ),
            )
            subprocess.run(["git", "init", "-b", "main"], cwd=repository, check=True, capture_output=True)
            subprocess.run(["git", "add", "."], cwd=repository, check=True, capture_output=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=Test",
                    "-c",
                    "user.email=test@example.invalid",
                    "commit",
                    "-m",
                    "fixture",
                ],
                cwd=repository,
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "worktree", "add", "-b", "linked", str(linked)],
                cwd=repository,
                check=True,
                capture_output=True,
            )
            output = Path(temporary) / "output"
            result = subprocess.run(
                ["bash", "scripts/package-release.sh", "--source-only", str(output)],
                cwd=linked,
                env={
                    **os.environ,
                    "NAS_PREFLIGHT_REQUIRE_COMPLETE": "0",
                    "NAS_PREFLIGHT_SKIP_TESTS": "1",
                    "NAS_PREFLIGHT_SKIP_NIX": "1",
                },
                text=True,
                capture_output=True,
                timeout=90,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            provenance_files = list(output.glob("*.release/*.provenance.json"))
            self.assertEqual(len(provenance_files), 1)
            provenance = json.loads(provenance_files[0].read_text(encoding="utf-8"))
            self.assertEqual(provenance["fileSelectionPolicy"], "git-tracked-clean")
            self.assertNotEqual(provenance["gitCommit"], "unavailable")

    def test_cockpit_pure_modules_and_react_composition_have_direct_tests(self):
        modules = {path.stem for path in (ROOT / "cockpit" / "src").glob("*.js")}
        tested = {path.name.removesuffix(".test.mjs") for path in (ROOT / "tests" / "js").glob("*.test.mjs")}
        self.assertEqual(modules, tested & modules)
        self.assertIn("react-patternfly-source", tested)

    def test_identity_python_has_no_compressed_statement_lines(self):
        for filename in [
            "services/nas_identity_sync.py",
            "services/nas_identity_model.py",
            "services/nas_syncthing_devices.py",
            "services/nas_setup.py",
            "services/nas_setup_config.py",
        ]:
            for line_number, line in enumerate(text(filename).splitlines(), start=1):
                self.assertNotRegex(
                    line,
                    r";\s*(?:return|print|[A-Za-z_]\w*\s*=|os\.|handle\.)",
                    msg=f"compressed statement in {filename}:{line_number}",
                )

    def test_installed_preflight_uses_the_configured_source_checkout(self):
        preflight = text("scripts/preflight.sh")
        maintenance = text("modules/nas/internal/maintenance-tools.nix")
        self.assertIn('repo_root="${NAS_CONFIG_DIR:-', preflight)
        self.assertIn('cd -- "$repo_root"', preflight)
        self.assertIn("export NAS_CONFIG_DIR=", maintenance)

    def test_first_run_setup_is_packaged_secure_and_vm_exercised(self):
        setup = text("services/nas_setup.py") + text("services/nas_setup_config.py")
        identity = text("services/nas_identity_sync.py")
        tools = text("modules/nas/internal/account-tools.nix")
        system = text("modules/nas/config/system.nix")
        guest = text("tests/vm/guest-test.sh")
        encrypted_guest = text("tests/vm/encrypted-guest-test.sh")
        summary = text("docs/src/SUMMARY.md")
        self.assertIn('name = "nas-setup"', tools)
        self.assertIn("nasSetup", system)
        self.assertIn("(lib.lowPrio nasPythonApplication)", system)
        self.assertIn("d /var/lib/nas-setup 0770 root wheel -", system)
        self.assertRegex(
            tools,
            r'name = "first-run";\s+source = "/var/lib/nas-setup";[\s\S]*?rootMode = "0750";',
        )
        self.assertIn("def first_run", setup)
        self.assertIn("passwordFile", setup)
        self.assertIn("plaintext password", setup)
        self.assertIn("--confirm-storage-device", setup)
        self.assertIn("--allow-destructive-storage", setup)
        self.assertIn('"raidz3"', setup)
        self.assertIn("compression=zstd", setup)
        self.assertIn("require_setup_operator", setup)
        self.assertIn("maintained_sudo_authorization", setup)
        self.assertIn('["sudo", "-n", "--"', setup)
        self.assertIn("O_NOFOLLOW", setup)
        self.assertIn("stat.S_ISBLK", setup)
        self.assertIn("existing_account", setup)
        self.assertIn('"apply-accounts"', identity)
        self.assertIn("nasManagedBySetup", identity)
        self.assertIn("set_password/", identity)
        self.assertIn("nas-setup first-run", guest)
        self.assertIn("nas-setup account disable", guest)
        self.assertIn("alice-updated-password", guest)
        self.assertIn("nas-setup first-run", encrypted_guest)
        self.assertIn("[First start](admin/first-run.md)", summary)
        self.assertTrue((ROOT / "setup" / "first-run.example.json").exists())

    def test_unprivileged_tools_resolve_the_nixos_sudo_wrapper(self):
        wrapper_path = "export PATH=/run/wrappers/bin:$PATH"
        expected_wrappers = {
            "modules/nas/internal/account-tools.nix": 1,
            "modules/nas/internal/maintenance-tools.nix": 1,
            "modules/nas/internal/secret-tools.nix": 1,
            "modules/nas/internal/zfs-tools.nix": 3,
        }
        for filename, count in expected_wrappers.items():
            source = text(filename)
            self.assertNotIn("pkgs.sudo", source, msg=filename)
            self.assertEqual(source.count(wrapper_path), count, msg=filename)

    def test_browser_authorization_matrix_is_exercised_in_qemu(self):
        browser = text("tests/browser/authz.py")
        vm = text("tests/nixos/vm-common.nix")
        guest = text("tests/vm/guest-test.sh")
        self.assertIn("webdriver.Chrome", browser)
        self.assertIn("nas-user-settings", browser)
        self.assertIn("/share/not-a-real-token", browser)
        self.assertIn("chromedriver", vm)
        self.assertIn("pythonPackages.selenium", vm)
        self.assertIn("tests/browser/authz.py", guest)

    def test_browser_fixture_assigns_authentik_flow_roles_correctly(self):
        guest = text("tests/vm/guest-test.sh")
        self.assertIn("default-authentication-flow", guest)
        self.assertIn("default-provider-authorization-implicit-consent", guest)
        self.assertIn("authentication_flow:$authentication", guest)
        self.assertIn("authorization_flow:$authorization", guest)

    def test_nix_matrix_covers_reusable_profiles_and_rejected_configurations(self):
        flake = text("flake.nix")
        workflow = text(".github/workflows/ci.yml")
        matrix = text("scripts/nix-config-matrix.sh")
        negative = text("scripts/nix-negative-tests.sh")
        host_platform = text("modules/nas/config/host-platform.nix")
        consumer = text("tests/nixos/module-consumer.nix")
        for name in [
            "nas-module-consumer",
            "nas-profile-core-storage",
            "nas-profile-identity-sharing",
            "nas-profile-observability",
            "nas-profile-virtualization",
            "nas-profile-local-ai",
            "nas-profile-all",
        ]:
            self.assertIn(name, flake)
            self.assertIn(name, matrix)
        self.assertIn("nix-config-matrix.sh", workflow)
        self.assertIn("nix flake metadata --json", matrix)
        self.assertIn("nixosConfigurations.nas", matrix)
        self.assertIn("root file system", matrix)
        self.assertIn("nix-negative-tests.sh", matrix)
        self.assertIn("trusted-loopback.nix", negative)
        self.assertIn("trusted-duplicate.nix", negative)
        self.assertIn("zfs-dataset-root.nix", negative)
        self.assertIn('"other/nas"', text("tests/nixos/invalid/zfs-dataset-root.nix"))
        self.assertIn("tftp-privileged-port.nix", negative)
        self.assertIn("replication-same-dataset.nix", negative)
        self.assertIn('"tank/nas"', text("tests/nixos/invalid/replication-same-dataset.nix"))
        self.assertIn("firewall-without-networking.nix", negative)
        self.assertIn("failed for the wrong reason", negative)
        self.assertIn('NAS_NEGATIVE_ROOT="$ROOT" NAS_NEGATIVE_FIXTURE="$fixture"', negative)
        negative_eval = text("tests/nixos/negative-eval.nix")
        self.assertIn('builtins.getEnv "NAS_NEGATIVE_ROOT"', negative_eval)
        self.assertIn('builtins.getEnv "NAS_NEGATIVE_FIXTURE"', negative_eval)
        self.assertIn('name == "open-webui"', host_platform)
        self.assertNotIn("allowUnfree = true", host_platform)
        self.assertIn("!cfg.testing.readOnlyPackageSet", host_platform)
        self.assertIn("nas.testing.readOnlyPackageSet = true", text("tests/nixos/integration.nix"))
        self.assertIn("nas.testing.readOnlyPackageSet = true", text("tests/nixos/encrypted.nix"))
        self.assertIn("TestFixtureOnlyKeyMaterial", consumer)

    def test_qemu_harness_covers_native_and_installed_paths(self):
        flake = text("flake.nix")
        host = text("scripts/qemu-test.sh")
        guest = text("tests/vm/guest-test.sh")
        run_vm = text("test/qemu/run-vm.sh")
        workflow = text(".github/workflows/ci.yml")
        self.assertIn("pkgs.testers.runNixOSTest", text("tests/nixos/integration.nix"))
        self.assertIn("pkgs.testers.runNixOSTest", text("tests/nixos/encrypted.nix"))
        self.assertIn("TestFixtureOnlyKeyMaterial", text("tests/nixos/integration.nix"))
        self.assertIn("TestFixtureOnlyKeyMaterial", text("tests/nixos/encrypted.nix"))
        self.assertIn("nas-vm-encrypted", flake)
        self.assertIn("nas-vm-encrypted-guest-test /dev/vdb", text("tests/nixos/encrypted.nix"))
        self.assertIn("nixosConfigurations.nas-qemu", flake)
        self.assertIn("checks.x86_64-linux", flake)
        self.assertIn("latest-nixos-minimal-x86_64-linux.iso", host)
        self.assertIn("[[ $MODE == boot ]] || ensure_iso", run_vm)
        self.assertIn("sha256sum --check --status", host)
        self.assertIn("nixos-install", text("tests/vm/install-system.sh"))
        self.assertIn("nas-vm-guest-test /dev/vdb", host)
        self.assertIn("NAS_QEMU_GUEST_TEST_TIMEOUT", host)
        reconfigure = text("tests/vm/reconfigure-system.sh")
        self.assertIn("nas-vm-reconfigure-test", host)
        self.assertIn("nixos-rebuild", reconfigure)
        self.assertIn("dry-activate", reconfigure)
        self.assertIn("test --flake", reconfigure)
        self.assertIn("switch --flake", reconfigure)
        self.assertIn("switch --rollback", reconfigure)
        self.assertIn("intentional QEMU rejected-candidate test", reconfigure)
        self.assertIn("nas-generation-test", reconfigure)
        self.assertIn("post-switch-console.log", host)
        self.assertIn("post-switch VM did not become reachable", host)
        self.assertNotIn("run_dynamic_web_scan", host)
        self.assertNotIn("NAS_ZAP_IMAGE", host)
        self.assertIn("hostfwd=tcp:127.0.0.1:$HTTPS_PORT-:443", host)
        self.assertIn("hostfwd=tcp:127.0.0.1:$COCKPIT_PORT-:9092", host)
        self.assertIn("zap-fuzz-evidence", workflow)
        self.assertIn('NAS_ZAP_CONFIRM_ACTIVE: "1"', workflow)
        self.assertNotIn("adversarial-installed.py", guest)
        installer = text("tests/vm/install-system.sh")
        self.assertGreaterEqual(installer.count("nixos-install"), 2)
        self.assertIn("reinstall-sentinel", installer)
        self.assertIn("source_fingerprint", host)
        self.assertIn("stage_source_tree", host)
        self.assertIn("QEMU source contains a symlink", host)
        self.assertIn("QEMU source contains a non-regular object", host)
        self.assertIn("path=$source_stage,mount_tag=nas-source", host)
        self.assertNotIn("path=$ROOT,mount_tag=nas-source", host)
        self.assertIn('rm -f "$data_disk"', host)
        self.assertIn("ssh-keygen -q -t ed25519", host)
        self.assertIn("PasswordAuthentication=no", host)
        self.assertNotIn("sshpass", host)
        vm_common = text("tests/nixos/vm-common.nix")
        self.assertIn("PasswordAuthentication = lib.mkForce false", vm_common)
        self.assertIn('(pkgs.writeText "vm-admin-password-hash" "$6$nixosnas$', vm_common)
        self.assertNotIn("authorizedKeys.keys", vm_common)
        self.assertIn("TestFixtureOnlyKeyMaterial", text("tests/nixos/qemu-installed.nix"))
        self.assertIn("NAS_INSTALL_SSH_PUBLIC_KEY", text("tests/vm/install-system.sh"))
        self.assertIn("nas-secrets activate-stdin", guest)
        self.assertIn("nas-setup first-run", guest)
        self.assertIn("nas-setup account apply", guest)
        self.assertIn("/authorize?scope=files", guest)
        self.assertIn("open-webui.service", guest)
        self.assertIn("nas-managed-services-control status", guest)
        self.assertIn("nas-managed-services-control document", guest)
        self.assertIn("nas-managed-services-control set ", guest)
        self.assertIn("nas-managed-services-control set-many", guest)
        self.assertIn("nas-managed-services-control wake", guest)
        self.assertIn("nas-managed-services-control set grafana", guest)
        self.assertIn("ai-runtime", guest)
        self.assertIn("ai-workspace", guest)
        self.assertIn("ai-downloader", guest)
        self.assertNotIn("nas-feature-control", guest)
        self.assertNotIn("nas-migrate-state", guest)
        self.assertNotIn("aiRuntime", guest)
        self.assertNotIn("aiWorkspace", guest)
        self.assertIn("syncthing_config=/var/lib/syncthing/.config/syncthing/config.xml", guest)
        self.assertIn('REMOTE = "tftp/qemu-tftp.txt"', guest)
        self.assertIn("read-only TFTP accepted a write request", guest)
        self.assertIn("Created post-restore marker", guest)
        self.assertIn("nas-identity-sync sync-syncthing", guest)
        self.assertIn('systemctl cat "$unit"', guest)
        self.assertIn("NAS_PREFLIGHT_VERIFY_MANIFEST=0 nas-preflight", guest)
        self.assertIn("check: nas-vm", workflow)
        self.assertIn("check: nas-vm-encrypted", workflow)
        self.assertNotIn("nixosConfigurations.nas.config.system.build.toplevel", workflow)
        bundle_import = workflow.index("Reassemble cached Nix store bundles before configuration builds")
        system_build = workflow.index("Build missing testable systems")
        bundle_publish = workflow.index("Publish the exact Nix bundles used by this run")
        self.assertLess(bundle_import, system_build)
        self.assertLess(system_build, bundle_publish)
        self.assertIn("Export missing Nix store bundles for downstream VMs", workflow)
        self.assertIn("steps.vm_bundle_handoff.outputs.cache_complete != 'true'", workflow)
        integration_import = workflow.index("Reassemble Nix store from the build handoff")
        integration_run = workflow.index("Run ${{ matrix.vm }} NixOS VM integration tests")
        self.assertLess(integration_import, integration_run)


if __name__ == "__main__":
    unittest.main()
