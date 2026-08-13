from __future__ import annotations

import gzip
import os
import pathlib
import re
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "vm-bundles.sh"

EXPECTED_BUNDLES = [
    "core",
    "copyparty",
    "caddy",
    "identity",
    "observability",
    "storage",
    "ai",
    "test-browser",
    "test-tools",
    "vm-drivers",
]

FAKE_NIX = """\
#!/usr/bin/env bash
set -eu
if [[ ${NIX_STORE:-} == nix-store ]]; then
  echo "NIX_STORE was overwritten by the bundle helper" >&2
  exit 91
fi
printf '%s\\n' "$*" >> "$NAS_TEST_NIX_LOG"
case "$1" in
  eval)
    ref=${3%.outPath}
    case "$ref" in
      .#checks.x86_64-linux.nas-vm.driver) name=nas-vm-driver ;;
      .#checks.x86_64-linux.nas-vm-encrypted.driver) name=nas-vm-encrypted-driver ;;
      *)
        name=${ref##*.x86_64-linux.}
        ;;
    esac
    printf '/nix/store/aaaaaaaaaa-%s' "$name"
    ;;
  path-info)
    shift 2
    for path in "$@"; do
      printf '%s\\n' "$path"
      case "$path" in
        */core) ;;
        *) printf '%s\\n' /nix/store/aaaaaaaaaa-core ;;
      esac
    done
    ;;
esac
"""

FAKE_NIX_STORE = """\
#!/usr/bin/env bash
set -eu
printf '%s\\n' "$*" >> "$NAS_TEST_NIX_STORE_LOG"
case "$*" in
  --export*)
    for arg in "$@"; do
      [[ $arg == --export ]] && continue
      printf 'NAR:%s\\n' "$arg"
    done
    ;;
  --import)
    printf 'import:%s\\n' "$(head -n1)" >> "$NAS_TEST_NIX_STORE_LOG"
    ;;
esac
"""


class VmBundleScriptTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self._root = pathlib.Path(self._temporary.name)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def _run(self, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(SCRIPT), *args],
            cwd=ROOT,
            env=env or os.environ.copy(),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    def _fake_environment(self) -> tuple[dict[str, str], pathlib.Path, pathlib.Path]:
        env = os.environ.copy()
        env["PATH"] = f"{self._root}:{env.get('PATH', '')}"
        nix_log = self._root / "nix.log"
        nix_store_log = self._root / "nix-store.log"
        (self._root / "nix").write_text(FAKE_NIX, encoding="utf-8")
        (self._root / "nix").chmod(0o755)
        (self._root / "nix-store").write_text(FAKE_NIX_STORE, encoding="utf-8")
        (self._root / "nix-store").chmod(0o755)
        env["NAS_TEST_NIX_LOG"] = str(nix_log)
        env["NAS_TEST_NIX_STORE_LOG"] = str(nix_store_log)
        return env, nix_log, nix_store_log

    def test_list_lists_core_first_then_each_application(self) -> None:
        result = self._run("list")
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertEqual(result.stdout.splitlines(), EXPECTED_BUNDLES)
        self.assertEqual(result.stdout.splitlines()[0], "core")

    def test_help_is_safe_and_documents_subcommands(self) -> None:
        for flag in ("--help", "-h"):
            with self.subTest(flag=flag):
                result = self._run(flag)
                self.assertEqual(result.returncode, 0)
                self.assertIn("usage", (result.stdout + result.stderr).lower())

    def test_unknown_subcommand_fails_cleanly(self) -> None:
        result = self._run("not-a-verb")
        self.assertEqual(result.returncode, 1)
        self.assertIn("unknown subcommand", result.stderr)

    def test_flake_packages_match_script_bundle_manifest(self) -> None:
        flake = (ROOT / "flake.nix").read_text(encoding="utf-8")
        block = flake.split("\n      packages.x86_64-linux =", 1)[1]
        block = block.split("\n      devShells.x86_64-linux.test =", 1)[0]
        block = block.split("\n        in {", 1)[1]
        declared = set(re.findall(r"^\s{10}([a-zA-Z0-9][a-zA-Z0-9-]*)\s*=", block, flags=re.MULTILINE))
        self.assertEqual(declared, set(EXPECTED_BUNDLES))

    def test_keys_emits_github_output_lines_and_key_files(self) -> None:
        env, _, _ = self._fake_environment()
        out_dir = self._root / "keys"
        result = self._run("keys", str(out_dir), env=env)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        lines = result.stdout.splitlines()
        self.assertEqual(len(lines), len(EXPECTED_BUNDLES))
        for name in EXPECTED_BUNDLES:
            expected_hash = {
                "core": "aaaaaaaaaa",
                "vm-drivers": "aaaaaaaaaa-aaaaaaaaaa-aaaaaaaaaa-aaaaaaaaaa",
            }.get(name, "aaaaaaaaaa-aaaaaaaaaa")
            expected = f"key_{name.replace('-', '_')}={expected_hash}"
            self.assertIn(expected, lines)
            self.assertEqual((out_dir / f"{name}.key").read_text(encoding="utf-8").strip(), expected_hash)

    def test_vm_drivers_key_tracks_core_and_both_exact_nixos_test_drivers(self) -> None:
        env, nix_log, _ = self._fake_environment()
        env["NIX_STORE"] = "/nix/store"
        result = self._run("keys", env=env)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        calls = nix_log.read_text(encoding="utf-8").splitlines()
        self.assertIn(
            "eval --raw .#checks.x86_64-linux.nas-vm.driver.outPath",
            calls,
        )
        self.assertIn(
            "eval --raw .#checks.x86_64-linux.nas-vm-encrypted.driver.outPath",
            calls,
        )
        self.assertIn("key_vm_drivers=aaaaaaaaaa-aaaaaaaaaa-aaaaaaaaaa-aaaaaaaaaa", result.stdout.splitlines())

    def test_save_batches_build_then_exports_core_first_and_application_deltas(self) -> None:
        env, nix_log, nix_store_log = self._fake_environment()
        out_dir = self._root / "bundles"
        result = self._run("save", str(out_dir), env=env)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

        for name in EXPECTED_BUNDLES:
            with self.subTest(bundle=name):
                self.assertTrue((out_dir / f"{name}.nar.gz").is_file(), name)

        with gzip.open(out_dir / "core.nar.gz", "rb") as stream:
            self.assertEqual(stream.read().decode(), "NAR:/nix/store/aaaaaaaaaa-core\n")
        with gzip.open(out_dir / "copyparty.nar.gz", "rb") as stream:
            self.assertEqual(stream.read().decode(), "NAR:/nix/store/aaaaaaaaaa-copyparty\n")

        nix_calls = nix_log.read_text(encoding="utf-8").splitlines()
        build_calls = [call for call in nix_calls if call.startswith("build --no-link ")]
        expected_build = "build --no-link " + " ".join(
            [f".#packages.x86_64-linux.{name}" for name in EXPECTED_BUNDLES]
            + [
                ".#checks.x86_64-linux.nas-vm.driver",
                ".#checks.x86_64-linux.nas-vm-encrypted.driver",
            ]
        )
        self.assertEqual(build_calls, [expected_build])
        self.assertIn(
            "path-info -r /nix/store/aaaaaaaaaa-vm-drivers "
            "/nix/store/aaaaaaaaaa-nas-vm-driver "
            "/nix/store/aaaaaaaaaa-nas-vm-encrypted-driver",
            nix_calls,
        )

        store_calls = nix_store_log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len([c for c in store_calls if c.startswith("--export")]), len(EXPECTED_BUNDLES))
        driver_export = next(c for c in store_calls if c.startswith("--export") and "nas-vm-driver" in c)
        self.assertIn("/nix/store/aaaaaaaaaa-nas-vm-driver", driver_export)
        self.assertIn("/nix/store/aaaaaaaaaa-nas-vm-encrypted-driver", driver_export)
        self.assertIn("/nix/store/aaaaaaaaaa-vm-drivers", driver_export)
        self.assertNotIn("/nix/store/aaaaaaaaaa-core", driver_export)

    def test_import_restores_core_first(self) -> None:
        env, _, nix_store_log = self._fake_environment()
        in_dir = self._root / "bundles"
        in_dir.mkdir()
        for name in ("core", "copyparty", "identity"):
            with gzip.open(in_dir / f"{name}.nar.gz", "wb") as stream:
                stream.write(f"NAR:/nix/store/aaaaaaaaaa-{name}\n".encode())

        result = self._run("import", str(in_dir), env=env)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        imports = [
            line.removeprefix("import:")
            for line in nix_store_log.read_text(encoding="utf-8").splitlines()
            if line.startswith("import:")
        ]
        self.assertEqual(
            imports,
            [
                "NAR:/nix/store/aaaaaaaaaa-core",
                "NAR:/nix/store/aaaaaaaaaa-copyparty",
                "NAR:/nix/store/aaaaaaaaaa-identity",
            ],
        )

    def test_import_builds_missing_core_before_restoring_cached_deltas(self) -> None:
        env, nix_log, nix_store_log = self._fake_environment()
        in_dir = self._root / "bundles"
        in_dir.mkdir()
        with gzip.open(in_dir / "test-tools.nar.gz", "wb") as stream:
            stream.write(b"NAR:/nix/store/aaaaaaaaaa-test-tools\n")

        result = self._run("import", str(in_dir), env=env)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertIn("core bundle archive is unavailable", result.stderr)
        self.assertIn(
            "build --no-link .#packages.x86_64-linux.core",
            nix_log.read_text(encoding="utf-8").splitlines(),
        )
        imports = [
            line.removeprefix("import:")
            for line in nix_store_log.read_text(encoding="utf-8").splitlines()
            if line.startswith("import:")
        ]
        self.assertEqual(imports, ["NAR:/nix/store/aaaaaaaaaa-test-tools"])

    def test_save_requires_a_directory_argument(self) -> None:
        result = self._run("save")
        self.assertEqual(result.returncode, 1)
        self.assertIn("save requires exactly one directory", result.stderr)

    def test_save_missing_preserves_existing_archives(self) -> None:
        env, _, nix_store_log = self._fake_environment()
        out_dir = self._root / "bundles"
        out_dir.mkdir()
        with gzip.open(out_dir / "core.nar.gz", "wb") as stream:
            stream.write(b"existing-core\n")

        result = self._run("save-missing", str(out_dir), env=env)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        with gzip.open(out_dir / "core.nar.gz", "rb") as stream:
            self.assertEqual(stream.read(), b"existing-core\n")
        exports = [
            line for line in nix_store_log.read_text(encoding="utf-8").splitlines() if line.startswith("--export")
        ]
        self.assertEqual(len(exports), len(EXPECTED_BUNDLES) - 1)

    def test_import_requires_a_directory_argument(self) -> None:
        result = self._run("import")
        self.assertEqual(result.returncode, 1)
        self.assertIn("import requires exactly one directory", result.stderr)


if __name__ == "__main__":
    unittest.main()
