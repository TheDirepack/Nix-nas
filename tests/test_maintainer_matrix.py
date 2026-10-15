from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import re
import subprocess
import sys
import unittest

from maintainer_test_base import MaintainerScriptMixin

EVIDENCE_WRITER = """
import hashlib, json
lib = pathlib.Path(args[args.index('-v', args.index('-v') + 1) + 1].split(':', 1)[0])
lock = lib / 'zap-addons.lock.json'
evidence = {
    'image': os.environ['NAS_ZAP_IMAGE'],
    'runtimeImage': os.environ['NAS_ZAP_RUNTIME_IMAGE'],
    'lockSha256': hashlib.sha256(lock.read_bytes()).hexdigest(),
    'runnableVerified': True,
    'addons': json.loads(lock.read_text())['addons'],
    'sourceBuild': json.loads(lock.read_text())['sourceBuild'],
}
"""

IMAGE_BUILDER = """
args = sys.argv[1:]
if args[0] == 'build':
    assert '--pull=false' in args
    assert '--build-arg' in args
    pathlib.Path(args[args.index('--iidfile') + 1]).write_text('sha256:' + 'b' * 64)
    raise SystemExit(int(os.environ.get('FAKE_BUILD_RC', '0')))
"""


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
            self.assertIn('selected = ("source", "security")', matrix_source)
        finally:
            sys.modules.pop(spec.name, None)

    def test_smart_fuzz_entrypoints_expose_organized_suites(self) -> None:
        direct = self.run_clean(sys.executable, "scripts/fuzz.py", "--help")
        self.assertEqual(direct.returncode, 0, direct.stdout + direct.stderr)
        self.assertIn("Hypothesis", direct.stdout + direct.stderr)

        orchestrator = self.run_clean(sys.executable, "scripts/run-fuzz.py", "--help")
        self.assertEqual(orchestrator.returncode, 0, orchestrator.stdout + orchestrator.stderr)
        help_text = orchestrator.stdout + orchestrator.stderr
        for suite in (
            "boundaries",
            "custom-inputs",
            "properties",
            "stateful",
            "security",
            "javascript",
            "executable-contracts",
        ):
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
"""
            + IMAGE_BUILDER
            + """
if os.environ.get('FAKE_ZAP_SLEEP'):
    time.sleep(float(os.environ['FAKE_ZAP_SLEEP']))
args=sys.argv[1:]
mount=args[args.index('-v')+1]
out=pathlib.Path(mount.split(':',1)[0])
for flag in ('-r','-J','-w'):
    name=args[args.index(flag)+1]
    (out/name).write_text('ok\\n', encoding='utf-8')
evidence = next(arg for arg in args if arg.startswith('NAS_ZAP_ADDON_EVIDENCE=')).split('=', 1)[1]
evidence_path = out/pathlib.Path(evidence).name
"""
            + EVIDENCE_WRITER
            + """
evidence_path.write_text(json.dumps(evidence), encoding='utf-8')
pathlib.Path(out/'invocation.txt').write_text('\\n'.join(args), encoding='utf-8')
sys.exit(int(os.environ.get('FAKE_ZAP_RC', '0')))
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
        self.assertIn(f"--user\n{os.getuid()}:{os.getgid()}\n", invocation)
        self.assertIn("JAVA_TOOL_OPTIONS=-Duser.home=/tmp", invocation)
        self.assertIn("HOME=/tmp", invocation)
        self.assertIn("--add-host\nnas-test.local:127.0.0.1", invocation)
        self.assertIn("zap-baseline.py", invocation)
        self.assertIn("/nas-zap/zap-entrypoint.sh", invocation)
        self.assertIn("sha256:" + "b" * 64, invocation)
        self.assertIn("https://nas-test.local:8443/", invocation)
        self.assertNotIn("\n-I\n", f"\n{invocation}\n")
        self.assertTrue((reports / "zap-scan-baseline.json").is_file())
        self.assertIn("-c\nzap-packaged.conf", invocation)
        rules = (reports / "zap-packaged.conf").read_text(encoding="utf-8")
        configured = [line.split("\t")[:2] for line in rules.splitlines() if line and not line.startswith("#")]
        self.assertEqual(configured, [["10015", "INFO"], ["10049", "INFO"], ["10109", "INFO"]])
        warning = subprocess.run(
            ["bash", "scripts/zap-scan.sh", "baseline", "https://nas-test.local:8443/"],
            cwd=self.clean_root,
            env={**env, "FAKE_ZAP_RC": "2"},
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(warning.returncode, 2)
        self.assertIn("warnings are fatal", warning.stderr)

        rejected_build = subprocess.run(
            ["bash", "scripts/zap-scan.sh", "baseline", "https://nas-test.local:8443/"],
            cwd=self.clean_root,
            env={**env, "FAKE_BUILD_RC": "1"},
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(rejected_build.returncode, 2)
        self.assertIn("source-built scanner", rejected_build.stderr)

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

    def test_zap_wrappers_require_reports_from_the_current_scan(self) -> None:
        fake_bin = pathlib.Path(self._temporary.name) / "fresh-evidence-bin"
        fake_bin.mkdir()
        runtime = fake_bin / "docker"
        runtime.write_text(
            "#!/usr/bin/env python3\n"
            "import os, pathlib, sys\n" + IMAGE_BUILDER + "args = sys.argv[1:]\n"
            "out = pathlib.Path(args[args.index('-v') + 1].split(':', 1)[0])\n"
            "for name in os.environ['CURRENT_REPORTS'].split(','):\n"
            "    if name:\n"
            "        (out / name).write_text('current scan\\n')\n"
            + EVIDENCE_WRITER
            + "for name in os.environ['CURRENT_REPORTS'].split(','):\n"
            "    if name.endswith('.addons.json'):\n"
            "        (out / name).write_text(json.dumps(evidence))\n"
            "raise SystemExit(int(os.environ['CURRENT_STATUS']))\n",
            encoding="utf-8",
        )
        runtime.chmod(0o755)
        scans = (
            ("zap-scan.sh", "baseline", "zap-scan-baseline", ("html", "json", "md", "addons.json")),
            ("zap-scan.sh", "full", "zap-scan-full", ("html", "json", "md", "addons.json")),
            (
                "zap-automation-scan.sh",
                "unauthenticated",
                "zap-automation-unauthenticated",
                ("html", "json", "addons.json"),
            ),
            (
                "zap-automation-scan.sh",
                "authenticated",
                "zap-automation-authenticated",
                ("html", "json", "addons.json"),
            ),
        )
        for script, mode, prefix, suffixes in scans:
            names = [f"{prefix}.{suffix}" for suffix in suffixes]
            cases = (([], 0), (names[:1], 0), (names[:-1], 0), (names, 0), (names, 2))
            for index, (current, status) in enumerate(cases):
                with self.subTest(script=script, mode=mode, reports=current, scanner_status=status):
                    out = pathlib.Path(self._temporary.name) / f"evidence-{mode}-{index}"
                    out.mkdir()
                    for name in names:
                        (out / name).write_text("stale scan\n", encoding="utf-8")
                    unrelated = out / "other-scan.json"
                    unrelated.write_text("preserve other scan\n", encoding="utf-8")
                    result = subprocess.run(
                        ["bash", f"scripts/{script}", mode, "https://127.0.0.1/"],
                        cwd=self.clean_root,
                        env={
                            **os.environ,
                            "PATH": f"{fake_bin}:{os.environ.get('PATH', '')}",
                            "NAS_CONTAINER_RUNTIME": "docker",
                            "NAS_ZAP_IMAGE": "example.invalid/zap@sha256:" + "a" * 64,
                            "NAS_ZAP_OUT_DIR": str(out),
                            "NAS_ZAP_CONFIRM_ACTIVE": "1",
                            "NAS_ZAP_AUTH_USER": "fixture-user",
                            "NAS_ZAP_AUTH_PASSWORD": "fixture-password",
                            "CURRENT_REPORTS": ",".join(current),
                            "CURRENT_STATUS": str(status),
                        },
                        text=True,
                        capture_output=True,
                        timeout=10,
                        check=False,
                    )
                    expected = 0 if current == names and status == 0 else 2
                    self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                    if status == 0 and current != names:
                        self.assertIn("did not produce expected report", result.stderr)
                    for name in names:
                        path = out / name
                        if name in current:
                            if name.endswith(".addons.json"):
                                self.assertTrue(json.loads(path.read_text())["runnableVerified"])
                            else:
                                self.assertEqual(path.read_text(), "current scan\n")
                        else:
                            self.assertFalse(path.exists(), f"stale evidence retained: {path}")
                    self.assertEqual(unrelated.read_text(), "preserve other scan\n")

    def test_zap_automation_preserves_scope_ownership_and_authentication_requirements(self) -> None:
        fake_bin = pathlib.Path(self._temporary.name) / "automation-bin"
        fake_bin.mkdir()
        runtime = fake_bin / "docker"
        runtime.write_text(
            "#!/usr/bin/env python3\n"
            "import os, pathlib, sys\n" + IMAGE_BUILDER + "args = sys.argv[1:]\n"
            "out = pathlib.Path(args[args.index('-v') + 1].split(':', 1)[0])\n"
            "(out / 'invocation.txt').write_text('\\n'.join(args))\n"
            "plan = pathlib.Path(next(arg for arg in args if arg.endswith('.yaml'))).name\n"
            "prefix = pathlib.Path(plan).stem\n"
            "for suffix in ('html', 'json'):\n"
            "    (out / (prefix + '.' + suffix)).write_text('ok')\n"
            "(out / 'captured-plan.json').write_bytes((out / plan).read_bytes())\n"
            + EVIDENCE_WRITER
            + "(out / (prefix + '.addons.json')).write_text(json.dumps(evidence))\n",
            encoding="utf-8",
        )
        runtime.chmod(0o755)
        for mode in ("unauthenticated", "authenticated"):
            with self.subTest(mode=mode):
                out = pathlib.Path(self._temporary.name) / f"automation-{mode}-reports"
                result = subprocess.run(
                    ["bash", "scripts/zap-automation-scan.sh", mode, "https://127.0.0.1:8443/console/"],
                    cwd=self.clean_root,
                    env={
                        **os.environ,
                        "PATH": f"{fake_bin}:{os.environ.get('PATH', '')}",
                        "NAS_CONTAINER_RUNTIME": "docker",
                        "NAS_ZAP_IMAGE": "example.invalid/zap@sha256:" + "a" * 64,
                        "NAS_ZAP_OUT_DIR": str(out),
                        "NAS_ZAP_CONFIRM_ACTIVE": "1",
                        "NAS_ZAP_AUTH_USER": "fixture-user",
                        "NAS_ZAP_AUTH_PASSWORD": "fixture-password",
                    },
                    text=True,
                    capture_output=True,
                    timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                invocation = (out / "invocation.txt").read_text()
                self.assertIn(f"--user\n{os.getuid()}:{os.getgid()}\n", invocation)
                self.assertIn("JAVA_TOOL_OPTIONS=-Duser.home=/tmp", invocation)
                self.assertIn("HOME=/tmp", invocation)
                self.assertIn("/nas-zap/zap-entrypoint.sh", invocation)
                self.assertIn("sha256:" + "b" * 64, invocation)
                plan = json.loads((out / "captured-plan.json").read_text())
                context = plan["env"]["contexts"][0]
                self.assertEqual(context["urls"], ["https://127.0.0.1:8443/console/"])
                self.assertEqual(context.get("includePaths"), [r"https://127\.0\.0\.1:8443/.*"])
                self.assertNotIn("excludePaths", context)
                spider = next(job for job in plan["jobs"] if job["type"] == "spiderClient")
                if mode == "authenticated":
                    self.assertEqual(spider["parameters"]["user"], "nas-browser-user")
                    verification = context["authentication"]["verification"]
                    self.assertEqual(verification["method"], "poll")
                    self.assertEqual(verification["pollUrl"], "https://127.0.0.1:8443/identity/api/v3/core/users/me/")
                    self.assertRegex('{"user":{"username":"fixture-user"}}', verification["loggedInRegex"])
                    self.assertNotRegex('{"detail":"Not authenticated"}', verification["loggedInRegex"])
                    requestor = next((job for job in plan["jobs"] if job["type"] == "requestor"), None)
                    self.assertIsNotNone(requestor, "browser-only counters cannot verify an HTTP session")
                    assert requestor is not None
                    self.assertEqual(requestor["parameters"]["user"], "nas-browser-user")
                    self.assertEqual(requestor["requests"], [{"url": verification["pollUrl"], "responseCode": 200}])
                    self.assertIn(
                        {
                            "name": "private identity response verified",
                            "type": "url",
                            "url": verification["pollUrl"],
                            "operator": "and",
                            "requestHeaderRegex": "",
                            "requestBodyRegex": "",
                            "responseHeaderRegex": r"^HTTP/\d+(?:\.\d+)? 200(?:\s|$)",
                            "responseBodyRegex": verification["loggedInRegex"],
                            "onFail": "error",
                        },
                        requestor.get("tests", []),
                    )
                    identity_test = next(
                        test for test in requestor["tests"] if test["name"] == "private identity response verified"
                    )
                    for status, body, accepted in (
                        ("HTTP/1.1 200 OK", '{"username":"fixture-user"}', True),
                        ("HTTP/2 200 OK", '{"username":"fixture-user"}', True),
                        ("HTTP/1.1 500 Error", '{"username":"fixture-user"}', False),
                        ("HTTP/1.1 401 Unauthorized", '{"username":"fixture-user"}', False),
                        ("HTTP/1.1 302 Found", '{"username":"fixture-user"}', False),
                        ("HTTP/1.1 2000 Invalid", '{"username":"fixture-user"}', False),
                        ("HTTP/1.1 500 Error\r\nX-Detail: HTTP/1.1 200 OK", '{"username":"fixture-user"}', False),
                        ("HTTP/1.1 200 OK", '{"username":"another-user"}', False),
                        ("HTTP/1.1 200 OK", '{"detail":"Not authenticated"}', False),
                    ):
                        with self.subTest(status=status, body=body):
                            self.assertEqual(
                                all(
                                    re.search(identity_test[key], value) is not None
                                    for key, value in (
                                        ("requestHeaderRegex", "GET /identity/api/v3/core/users/me/ HTTP/1.1"),
                                        ("requestBodyRegex", ""),
                                        ("responseHeaderRegex", status + "\r\nContent-Type: application/json\r\n"),
                                        ("responseBodyRegex", body),
                                    )
                                ),
                                accepted,
                            )
                    self.assertIn(
                        {
                            "name": "authenticated session verified",
                            "type": "stats",
                            "statistic": "stats.auth.state.loggedin",
                            "site": "https://127.0.0.1:8443",
                            "operator": ">=",
                            "value": 1,
                            "onFail": "error",
                        },
                        requestor.get("tests", []),
                    )
                    self.assertNotIn("fixture-password", json.dumps(plan))
                else:
                    self.assertNotIn("tests", spider)
                    self.assertNotIn("authentication", context)

    def test_zap_wrappers_reject_corrupt_or_incomplete_native_evidence(self) -> None:
        fake_bin = pathlib.Path(self._temporary.name) / "invalid-evidence-bin"
        fake_bin.mkdir()
        runtime = fake_bin / "docker"
        runtime.write_text(
            "#!/usr/bin/env python3\n"
            "import os, pathlib, sys\n" + IMAGE_BUILDER + "args = sys.argv[1:]\n"
            "out = pathlib.Path(args[args.index('-v') + 1].split(':', 1)[0])\n"
            "if '-r' in args:\n"
            "    names = [args[args.index(flag) + 1] for flag in ('-r', '-J', '-w')]\n"
            "else:\n"
            "    names = ['zap-automation-' + os.environ['SCAN_MODE'] + '.' + suffix for suffix in ('html', 'json')]\n"
            "for name in names:\n"
            "    (out / name).write_text('fresh report')\n" + EVIDENCE_WRITER + "case = os.environ['BAD_EVIDENCE']\n"
            "if case == 'inventory': evidence['addons'].pop()\n"
            "if case == 'image': evidence['image'] = 'wrong image'\n"
            "if case == 'runtime-image': evidence['runtimeImage'] = 'sha256:' + 'c' * 64\n"
            "if case == 'hash': evidence['lockSha256'] = '0' * 64\n"
            "if case == 'unverified': evidence['runnableVerified'] = False\n"
            "name = next(arg for arg in args if arg.startswith('NAS_ZAP_ADDON_EVIDENCE=')).split('=', 1)[1]\n"
            "(out / pathlib.Path(name).name).write_text('corrupt' if case == 'corrupt' else json.dumps(evidence))\n",
            encoding="utf-8",
        )
        runtime.chmod(0o755)
        for script, mode in (
            ("zap-scan.sh", "baseline"),
            ("zap-scan.sh", "full"),
            ("zap-automation-scan.sh", "unauthenticated"),
            ("zap-automation-scan.sh", "authenticated"),
        ):
            for bad_evidence in ("corrupt", "inventory", "image", "runtime-image", "hash", "unverified"):
                with self.subTest(mode=mode, evidence=bad_evidence):
                    out = pathlib.Path(self._temporary.name) / f"invalid-{mode}-{bad_evidence}"
                    result = subprocess.run(
                        ["bash", f"scripts/{script}", mode, "https://127.0.0.1/"],
                        cwd=self.clean_root,
                        env={
                            **os.environ,
                            "PATH": f"{fake_bin}:{os.environ.get('PATH', '')}",
                            "NAS_CONTAINER_RUNTIME": "docker",
                            "NAS_ZAP_IMAGE": "example.invalid/zap@sha256:" + "a" * 64,
                            "NAS_ZAP_OUT_DIR": str(out),
                            "NAS_ZAP_CONFIRM_ACTIVE": "1",
                            "NAS_ZAP_AUTH_USER": "fixture-user",
                            "NAS_ZAP_AUTH_PASSWORD": "fixture-password",
                            "BAD_EVIDENCE": bad_evidence,
                            "SCAN_MODE": mode,
                        },
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    self.assertIn("add-on evidence", result.stderr)

    def test_zap_entrypoint_verifies_native_rules_before_running_any_scan(self) -> None:
        helper = self.clean_root / "scripts/lib/zap-entrypoint.sh"
        self.assertTrue(helper.is_file(), "ZAP does not enforce the locked native add-on inventory")
        fake_bin = pathlib.Path(self._temporary.name) / "locked-addon-bin"
        fake_bin.mkdir()
        events = pathlib.Path(self._temporary.name) / "locked-addon-events"
        for name in ("python3", "zap.sh", "zap-baseline.py", "zap-full-scan.py"):
            path = fake_bin / name
            path.write_text(
                "#!/usr/bin/env bash\n"
                'printf "%s\\n" "$0 $*" >> "$ADDON_EVENTS"\n'
                'if [[ "$*" == *verify-loaded* && "${REJECT_LOADED:-0}" == 1 ]]; then exit 1; fi\n'
            )
            path.chmod(0o755)
        homes = set()
        for scanner in ("zap-baseline.py", "zap-full-scan.py", "zap.sh"):
            for reject in (False, True):
                with self.subTest(scanner=scanner, reject=reject):
                    events.write_text("")
                    result = subprocess.run(
                        ["bash", str(helper), scanner, "scan-target"],
                        cwd=self.clean_root,
                        env={
                            **os.environ,
                            "TMPDIR": self._temporary.name,
                            "PATH": f"{fake_bin}:{os.environ.get('PATH', '')}",
                            "ADDON_EVENTS": str(events),
                            "REJECT_LOADED": "1" if reject else "0",
                            "NAS_ZAP_ADDON_EVIDENCE": "/zap/wrk/fixture-addons.json",
                        },
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    calls = events.read_text().splitlines()
                    self.assertEqual(result.returncode, 1 if reject else 0, result.stderr)
                    self.assertIn("prepare --home ", calls[0])
                    home = pathlib.Path(calls[0].split("--home ", 1)[1])
                    self.assertTrue(home.is_dir())
                    self.assertEqual(home.stat().st_mode & 0o777, 0o700)
                    self.assertNotIn(home, homes)
                    homes.add(home)
                    self.assertIn(f"zap.sh -cmd -silent -dir {home} -addonlist", calls[1])
                    self.assertIn(f"verify-loaded --home {home}", calls[2])
                    if reject:
                        self.assertEqual(len(calls), 3, "scan ran without its complete locked rules")
                    else:
                        self.assertIn(f"{scanner} scan-target", calls[3])
                        flags = f"-silent -dir {home}"
                        self.assertIn(flags, calls[3])
                        self.assertEqual("-z " in calls[3], scanner != "zap.sh")


if __name__ == "__main__":
    unittest.main()
