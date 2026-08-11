from __future__ import annotations

import importlib.util
import os
import pathlib
import subprocess
import sys
import unittest

from maintainer_test_base import MaintainerScriptMixin


class MaintainerMatrixTests(MaintainerScriptMixin, unittest.TestCase):
    def test_test_matrix_lists_tiers_and_writes_bounded_evidence(self) -> None:
        listed = self.run_clean(sys.executable, "scripts/test-matrix.py", "list")
        self.assertEqual(listed.returncode, 0, listed.stdout + listed.stderr)
        for tier in ("source", "security", "fuzz", "nix-config", "browser", "native", "installer"):
            self.assertIn(tier, listed.stdout)

        matrix_path = self.clean_root / "scripts/test-matrix.py"
        spec = importlib.util.spec_from_file_location("nas_test_matrix", matrix_path)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader if spec else None)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        try:
            spec.loader.exec_module(module)
            probe = module.Stage(
                "source",
                (
                    sys.executable,
                    "-c",
                    'import os; raise SystemExit(0 if os.environ.get("NAS_PREFLIGHT_REQUIRE_COMPLETE") == "1" else 9)',
                ),
                5,
            )
            required = module.run_stage(probe, require_complete_source=True)
            self.assertEqual(required["status"], "passed")
            fuzz_stage = module.stage_catalog()["fuzz"]
            self.assertEqual(fuzz_stage.requires, ("python3", "nix", "npm"))
            matrix_source = matrix_path.read_text(encoding="utf-8")
            self.assertIn("start_new_session=True", matrix_source)
            self.assertIn("os.killpg", matrix_source)
        finally:
            sys.modules.pop(spec.name, None)

    def test_smart_fuzz_entrypoints_expose_organized_suites(self) -> None:
        direct = self.run_clean(sys.executable, "scripts/fuzz.py", "--help")
        self.assertEqual(direct.returncode, 0, direct.stdout + direct.stderr)
        self.assertIn("Hypothesis", direct.stdout + direct.stderr)

        orchestrator = self.run_clean(sys.executable, "scripts/run-fuzz.py", "--help")
        self.assertEqual(orchestrator.returncode, 0, orchestrator.stdout + orchestrator.stderr)
        help_text = orchestrator.stdout + orchestrator.stderr
        for suite in ("boundaries", "properties", "stateful", "security", "javascript", "executable-contracts"):
            self.assertIn(suite, help_text)
        self.assertNotIn("--cases", help_text)
        self.assertNotIn("--seed", help_text)

        contracts = self.run_clean(sys.executable, "scripts/fuzz-executables.py", "--help")
        self.assertEqual(contracts.returncode, 0, contracts.stdout + contracts.stderr)
        self.assertIn("not a mutation fuzzer", contracts.stdout + contracts.stderr)

    def test_zap_wrapper_requires_digest_and_constructs_bounded_scan(self) -> None:
        missing = self.run_clean("bash", "scripts/zap-scan.sh", "baseline", "https://nas-test.local:8443/")
        self.assertEqual(missing.returncode, 2)
        self.assertIn("pinned to an immutable sha256 digest", missing.stderr)

        fake_bin = pathlib.Path(self._temporary.name) / "fake-zap-bin"
        fake_bin.mkdir(exist_ok=True)
        fake_runtime = fake_bin / "docker"
        fake_runtime.write_text(
            """#!/usr/bin/env python3
import os, pathlib, sys, time
if os.environ.get('FAKE_ZAP_SLEEP'):
    time.sleep(float(os.environ['FAKE_ZAP_SLEEP']))
args=sys.argv[1:]
mount=args[args.index('-v')+1]
out=pathlib.Path(mount.split(':',1)[0])
for flag in ('-r','-J','-w'):
    name=args[args.index(flag)+1]
    (out/name).write_text('ok\\n', encoding='utf-8')
pathlib.Path(out/'invocation.txt').write_text('\\n'.join(args), encoding='utf-8')
""",
            encoding="utf-8",
        )
        fake_runtime.chmod(0o755)
        reports = pathlib.Path(self._temporary.name) / "zap-reports"
        env = os.environ.copy()
        env.update(
            {
                "PATH": f"{fake_bin}:{env.get('PATH', '')}",
                "PYTHONDONTWRITEBYTECODE": "1",
                "NAS_ZAP_IMAGE": "example.invalid/zap@sha256:" + "a" * 64,
                "NAS_ZAP_OUT_DIR": str(reports),
                "NAS_ZAP_EXTRA_HOST": "nas-test.local:127.0.0.1",
            }
        )
        result = subprocess.run(
            ["bash", "scripts/zap-scan.sh", "baseline", "https://nas-test.local:8443/"],
            cwd=self.clean_root,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        invocation = (reports / "invocation.txt").read_text(encoding="utf-8")
        self.assertIn("--network\nhost", invocation)
        self.assertIn("--add-host\nnas-test.local:127.0.0.1", invocation)
        self.assertIn("zap-baseline.py", invocation)
        self.assertIn("https://nas-test.local:8443/", invocation)
        self.assertNotIn("\n-I\n", f"\n{invocation}\n")
        self.assertTrue((reports / "zap-scan-baseline.json").is_file())

        public = subprocess.run(
            ["bash", "scripts/zap-scan.sh", "baseline", "https://example.com/"],
            cwd=self.clean_root,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(public.returncode, 2)
        self.assertIn("target is not local/private", public.stderr)

        active = subprocess.run(
            ["bash", "scripts/zap-scan.sh", "full", "https://nas-test.local:8443/"],
            cwd=self.clean_root,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(active.returncode, 2)
        self.assertIn("NAS_ZAP_CONFIRM_ACTIVE=1", active.stderr)

        sleeping = env.copy()
        sleeping["FAKE_ZAP_SLEEP"] = "5"
        sleeping["NAS_ZAP_PROCESS_TIMEOUT_SECONDS"] = "1"
        timed_out = subprocess.run(
            ["bash", "scripts/zap-scan.sh", "baseline", "https://nas-test.local:8443/"],
            cwd=self.clean_root,
            env=sleeping,
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(timed_out.returncode, 2)
        self.assertIn("exceeded the outer 1s process deadline", timed_out.stderr)

        bad_host = env.copy()
        bad_host["NAS_ZAP_EXTRA_HOST"] = "nas-test.local:127.0.0.1\r\nInjected: yes"
        rejected = subprocess.run(
            ["bash", "scripts/zap-scan.sh", "baseline", "https://nas-test.local:8443/"],
            cwd=self.clean_root,
            env=bad_host,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(rejected.returncode, 2)
        self.assertIn("must be one line", rejected.stderr)

    def test_zap_automation_requires_explicit_active_scan_confirmation(self) -> None:
        result = self.run_clean(
            "env",
            "NAS_ZAP_IMAGE=example.invalid/zap@sha256:" + "a" * 64,
            "bash",
            "scripts/zap-automation-scan.sh",
            "unauthenticated",
            "https://127.0.0.1/",
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("NAS_ZAP_CONFIRM_ACTIVE=1", result.stderr)


if __name__ == "__main__":
    unittest.main()
