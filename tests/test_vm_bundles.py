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
    "identity",
    "observability",
    "storage",
    "vm-drivers",
]

# Every fake root gets a distinct content hash so a key that drops a dependency
# and substitutes an equal-valued root is distinguishable from the real key.
FAKE_HASHES = {
    "core": "cccccccccc",
    "identity": "iiiiiiiiii",
    "observability": "oooooooooo",
    "storage": "ssssssssss",
    "vm-drivers": "vvvvvvvvvv",
    "nas-vm-driver": "dddddddddd",
    "nas-vm-encrypted-driver": "eeeeeeeeee",
    "driver-shared": "hhhhhhhhhh",
}

DRIVER_KEY_ROOTS = (
    "core",
    "identity",
    "observability",
    "storage",
    "vm-drivers",
    "nas-vm-driver",
    "nas-vm-encrypted-driver",
)


def fake_path(name: str) -> str:
    return f"/nix/store/{FAKE_HASHES[name]}-{name}"


FAKE_NIX = """\
#!/usr/bin/env bash
set -eu
if [[ ${NIX_STORE:-} == nix-store ]]; then
  echo "NIX_STORE was overwritten by the bundle helper" >&2
  exit 91
fi
printf '%s\\n' "$*" >> "$NAS_TEST_NIX_LOG"

bundle_hash() {
  case "$1" in
{hash_cases}
    *) printf 'aaaaaaaaaa' ;;
  esac
}

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
    if [[ -n ${NAS_TEST_FAIL_EVAL:-} && $name == "$NAS_TEST_FAIL_EVAL" ]]; then
      echo "error: evaluation failed for $ref" >&2
      exit 1
    fi
    hash="$(bundle_hash "$name")"
    if [[ ${NAS_TEST_VARY_NAME:-} == "$name" ]]; then
      hash="${NAS_TEST_VARY_HASH:-zzzzzzzzzz}"
    fi
    printf '/nix/store/%s-%s' "$hash" "$name"
    ;;
  path-info)
    shift 2
    for path in "$@"; do
      printf '%s\\n' "$path"
      case "$path" in
      *-nas-vm-driver|*-nas-vm-encrypted-driver)
        printf '%s\\n' "/nix/store/$(bundle_hash driver-shared)-driver-shared"
        printf '%s\\n' "/nix/store/$(bundle_hash identity)-identity"
        ;;
      *-core) ;;
      *-vm-drivers)
        printf '%s\\n' "/nix/store/$(bundle_hash core)-core"
        printf '%s\\n' "/nix/store/$(bundle_hash identity)-identity"
        ;;
      *)
        printf '%s\\n' "/nix/store/$(bundle_hash core)-core"
        ;;
      esac
    done
    ;;
esac
""".replace(
    "{hash_cases}",
    "\n".join(f"    {name}) printf '{digest}' ;;" for name, digest in FAKE_HASHES.items()),
)

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

    def _driver_key(self, env: dict[str, str]) -> str:
        result = self._run("keys", env=env)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        for line in result.stdout.splitlines():
            if line.startswith("key_vm_drivers="):
                return line.split("=", 1)[1]
        self.fail(f"key_vm_drivers was not reported: {result.stdout!r}")

    def test_list_lists_core_before_applications_and_driver_delta(self) -> None:
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
            if name == "vm-drivers":
                expected_hash = "-".join(FAKE_HASHES[root] for root in DRIVER_KEY_ROOTS)
            elif name == "core":
                expected_hash = FAKE_HASHES["core"]
            else:
                expected_hash = f"{FAKE_HASHES['core']}-{FAKE_HASHES[name]}"
            expected = f"key_{name.replace('-', '_')}={expected_hash}"
            self.assertIn(expected, lines)
            self.assertEqual((out_dir / f"{name}.key").read_text(encoding="utf-8").strip(), expected_hash)

    def test_vm_drivers_key_changes_with_every_application_dependency(self) -> None:
        env, nix_log, _ = self._fake_environment()
        env["NIX_STORE"] = "/nix/store"
        baseline = self._driver_key(env)
        self.assertEqual(baseline, "-".join(FAKE_HASHES[root] for root in DRIVER_KEY_ROOTS))
        calls = nix_log.read_text(encoding="utf-8").splitlines()
        self.assertIn(
            "eval --raw .#checks.x86_64-linux.nas-vm.driver.outPath",
            calls,
        )
        self.assertIn(
            "eval --raw .#checks.x86_64-linux.nas-vm-encrypted.driver.outPath",
            calls,
        )
        for dependency in ("core", "identity", "observability", "storage"):
            with self.subTest(dependency=dependency):
                varied = dict(env)
                varied["NAS_TEST_VARY_NAME"] = dependency
                varied["NAS_TEST_VARY_HASH"] = "zzzzzzzzzz"
                self.assertNotEqual(self._driver_key(varied), baseline)

    def test_build_builds_every_bundle_root_including_both_drivers(self) -> None:
        env, nix_log, _ = self._fake_environment()
        result = self._run("build", env=env)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertEqual(
            nix_log.read_text(encoding="utf-8").splitlines(),
            [
                "build --no-link -L "
                ".#packages.x86_64-linux.core "
                ".#packages.x86_64-linux.identity "
                ".#packages.x86_64-linux.observability "
                ".#packages.x86_64-linux.storage "
                ".#packages.x86_64-linux.vm-drivers "
                ".#checks.x86_64-linux.nas-vm.driver "
                ".#checks.x86_64-linux.nas-vm-encrypted.driver",
            ],
        )

    def test_build_accepts_a_selected_bundle_root(self) -> None:
        env, nix_log, _ = self._fake_environment()
        result = self._run("build", "vm-drivers", env=env)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertEqual(
            nix_log.read_text(encoding="utf-8").splitlines(),
            [
                "build --no-link -L "
                ".#packages.x86_64-linux.vm-drivers "
                ".#checks.x86_64-linux.nas-vm.driver "
                ".#checks.x86_64-linux.nas-vm-encrypted.driver",
            ],
        )

    def test_save_batches_build_then_exports_core_app_deltas_and_driver_delta(self) -> None:
        env, nix_log, nix_store_log = self._fake_environment()
        out_dir = self._root / "bundles"
        result = self._run("save", str(out_dir), env=env)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

        for name in EXPECTED_BUNDLES:
            with self.subTest(bundle=name):
                self.assertTrue((out_dir / f"{name}.nar.gz").is_file(), name)

        with gzip.open(out_dir / "core.nar.gz", "rb") as stream:
            self.assertEqual(stream.read().decode(), f"NAR:{fake_path('core')}\n")
        with gzip.open(out_dir / "identity.nar.gz", "rb") as stream:
            self.assertEqual(stream.read().decode(), f"NAR:{fake_path('identity')}\n")
        self.assertTrue((out_dir / "vm-drivers.nar.gz").is_file())
        manifest = (out_dir / "bundle-manifest.tsv").read_text(encoding="utf-8")
        self.assertIn(f"vm-drivers\t{fake_path('nas-vm-driver')}", manifest)
        self.assertIn(f"identity\t{fake_path('identity')}", manifest)
        self.assertNotIn(f"vm-drivers\t{fake_path('identity')}", manifest)
        self.assertTrue((out_dir / "bundle-handoff.sha256").is_file())
        for name in EXPECTED_BUNDLES:
            self.assertTrue((out_dir / f"{name}.paths").is_file(), name)
        verified = self._run("verify-handoff", str(out_dir), env=env)
        self.assertEqual(verified.returncode, 0, verified.stderr)

        nix_calls = nix_log.read_text(encoding="utf-8").splitlines()
        build_calls = [call for call in nix_calls if call.startswith("build --no-link ")]
        expected_build = "build --no-link -L " + " ".join(
            [f".#packages.x86_64-linux.{name}" for name in EXPECTED_BUNDLES]
            + [
                ".#checks.x86_64-linux.nas-vm.driver",
                ".#checks.x86_64-linux.nas-vm-encrypted.driver",
            ]
        )
        self.assertEqual(build_calls, [expected_build])
        self.assertIn(
            "path-info -r "
            + " ".join(fake_path(name) for name in ("vm-drivers", "nas-vm-driver", "nas-vm-encrypted-driver")),
            nix_calls,
        )
        self.assertEqual(
            len([call for call in nix_calls if call.startswith("path-info -r ")]),
            len(EXPECTED_BUNDLES),
            "each bundle closure should be enumerated once per export",
        )

        store_calls = nix_store_log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len([c for c in store_calls if c.startswith("--export")]), len(EXPECTED_BUNDLES))
        driver_export = next(c for c in store_calls if c.startswith("--export") and "nas-vm-driver" in c)
        self.assertIn(fake_path("nas-vm-driver"), driver_export)
        self.assertIn(fake_path("nas-vm-encrypted-driver"), driver_export)
        self.assertIn(fake_path("vm-drivers"), driver_export)
        self.assertIn(fake_path("driver-shared"), driver_export)
        self.assertNotIn(fake_path("identity"), driver_export)
        self.assertNotIn(fake_path("core"), driver_export)

    def test_verify_rejects_duplicate_manifest_paths(self) -> None:
        env, _, _ = self._fake_environment()
        out_dir = self._root / "bundles"
        out_dir.mkdir()
        (out_dir / "bundle-manifest.tsv").write_text(
            "core\t/nix/store/shared\nvm-drivers\t/nix/store/shared\n", encoding="utf-8"
        )
        result = self._run("verify", str(out_dir), env=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate", result.stderr)

    def test_verify_handoff_rejects_missing_and_corrupt_archives(self) -> None:
        env, _, _ = self._fake_environment()
        out_dir = self._root / "handoff"
        out_dir.mkdir()
        for name in EXPECTED_BUNDLES:
            (out_dir / f"{name}.nar.gz").write_bytes(f"archive-{name}\n".encode())
        (out_dir / "bundle-manifest.tsv").write_text(
            "".join(f"{name}\t/nix/store/{name}\n" for name in EXPECTED_BUNDLES), encoding="utf-8"
        )
        files = [out_dir / f"{name}.nar.gz" for name in EXPECTED_BUNDLES] + [out_dir / "bundle-manifest.tsv"]
        checksums = subprocess.run(
            ["sha256sum", *(str(path.name) for path in files)],
            cwd=out_dir,
            text=True,
            capture_output=True,
            check=True,
        )
        (out_dir / "bundle-handoff.sha256").write_text(checksums.stdout, encoding="utf-8")
        result = self._run("verify-handoff", str(out_dir), env=env)
        self.assertEqual(result.returncode, 0, result.stderr)

        (out_dir / "vm-drivers.nar.gz").unlink()
        result = self._run("verify-handoff", str(out_dir), env=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("archive is missing", result.stderr)

        (out_dir / "vm-drivers.nar.gz").write_bytes(b"restored-but-corrupt\n")
        result = self._run("verify-handoff", str(out_dir), env=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum validation failed", result.stderr)

    def test_verify_partial_handoff_accepts_only_missing_archives(self) -> None:
        env, _, _ = self._fake_environment()
        out_dir = self._root / "partial-handoff"
        out_dir.mkdir()
        (out_dir / "vm-drivers.nar.gz").write_bytes(b"driver-archive\n")
        (out_dir / "bundle-manifest.tsv").write_text("vm-drivers\t/nix/store/driver\n", encoding="utf-8")
        checksums = subprocess.run(
            ["sha256sum", "vm-drivers.nar.gz", "bundle-manifest.tsv"],
            cwd=out_dir,
            text=True,
            capture_output=True,
            check=True,
        )
        (out_dir / "bundle-handoff.partial.sha256").write_text(checksums.stdout, encoding="utf-8")

        result = self._run("verify-partial-handoff", str(out_dir), env=env)
        self.assertEqual(result.returncode, 0, result.stderr)

        (out_dir / "vm-drivers.nar.gz").write_bytes(b"corrupt\n")
        result = self._run("verify-partial-handoff", str(out_dir), env=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum validation failed", result.stderr)

        (out_dir / "vm-drivers.nar.gz").unlink()
        result = self._run("verify-partial-handoff", str(out_dir), env=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("contains no archives", result.stderr)

    def test_import_restores_core_before_application_and_driver_deltas(self) -> None:
        env, _, nix_store_log = self._fake_environment()
        in_dir = self._root / "bundles"
        in_dir.mkdir()
        for name in EXPECTED_BUNDLES:
            with gzip.open(in_dir / f"{name}.nar.gz", "wb") as stream:
                stream.write(f"NAR:{fake_path(name)}\n".encode())

        result = self._run("import", str(in_dir), env=env)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        imports = [
            line.removeprefix("import:")
            for line in nix_store_log.read_text(encoding="utf-8").splitlines()
            if line.startswith("import:")
        ]
        self.assertEqual(
            imports,
            [f"NAR:{fake_path(name)}" for name in EXPECTED_BUNDLES],
        )

    def test_import_builds_missing_core_before_restoring_cached_deltas(self) -> None:
        env, nix_log, nix_store_log = self._fake_environment()
        in_dir = self._root / "bundles"
        in_dir.mkdir()
        with gzip.open(in_dir / "identity.nar.gz", "wb") as stream:
            stream.write(f"NAR:{fake_path('identity')}\n".encode())

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
        self.assertEqual(imports, [f"NAR:{fake_path('identity')}"])

    def test_save_requires_a_directory_argument(self) -> None:
        result = self._run("save")
        self.assertEqual(result.returncode, 1)
        self.assertIn("save requires exactly one directory", result.stderr)

    def test_save_missing_preserves_existing_archives(self) -> None:
        env, nix_log, nix_store_log = self._fake_environment()
        out_dir = self._root / "bundles"
        out_dir.mkdir()
        with gzip.open(out_dir / "core.nar.gz", "wb") as stream:
            stream.write(b"existing-core\n")

        result = self._run("save-missing", str(out_dir), env=env)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        with gzip.open(out_dir / "core.nar.gz", "rb") as stream:
            self.assertEqual(stream.read(), b"existing-core\n")
        build_calls = [
            call for call in nix_log.read_text(encoding="utf-8").splitlines() if call.startswith("build --no-link ")
        ]
        self.assertEqual(len(build_calls), 1)
        self.assertNotIn(".#packages.x86_64-linux.core", build_calls[0])
        exports = [
            line for line in nix_store_log.read_text(encoding="utf-8").splitlines() if line.startswith("--export")
        ]
        self.assertEqual(len(exports), len(EXPECTED_BUNDLES) - 1)

    def test_save_missing_can_reuse_roots_built_by_an_earlier_step(self) -> None:
        env, nix_log, nix_store_log = self._fake_environment()
        env["NAS_BUNDLE_SKIP_BUILD"] = "1"
        out_dir = self._root / "bundles"
        out_dir.mkdir()
        with gzip.open(out_dir / "core.nar.gz", "wb") as stream:
            stream.write(b"existing-core\n")

        result = self._run("save-missing", str(out_dir), env=env)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertNotIn("build --no-link", nix_log.read_text(encoding="utf-8"))
        self.assertEqual(
            len(
                [line for line in nix_store_log.read_text(encoding="utf-8").splitlines() if line.startswith("--export")]
            ),
            len(EXPECTED_BUNDLES) - 1,
        )

    def test_save_missing_reuses_cached_closure_manifests_for_existing_archives(self) -> None:
        env, nix_log, nix_store_log = self._fake_environment()
        env["NAS_BUNDLE_SKIP_BUILD"] = "1"
        out_dir = self._root / "bundles"
        out_dir.mkdir()
        for name in EXPECTED_BUNDLES[:-1]:
            with gzip.open(out_dir / f"{name}.nar.gz", "wb") as stream:
                stream.write(f"existing-{name}\n".encode())
            (out_dir / f"{name}.paths").write_text(fake_path(name) + "\n", encoding="utf-8")

        result = self._run("save-missing", str(out_dir), env=env)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        path_info_calls = [
            line for line in nix_log.read_text(encoding="utf-8").splitlines() if line.startswith("path-info -r ")
        ]
        self.assertEqual(len(path_info_calls), 1, path_info_calls)
        self.assertIn(fake_path("vm-drivers"), path_info_calls[0])
        self.assertTrue((out_dir / "vm-drivers.paths").is_file())
        self.assertTrue(
            any(line.startswith("--export") for line in nix_store_log.read_text(encoding="utf-8").splitlines())
        )

    def test_save_missing_enumerates_the_closure_when_the_archive_is_absent(self) -> None:
        env, nix_log, nix_store_log = self._fake_environment()
        env["NAS_BUNDLE_SKIP_BUILD"] = "1"
        out_dir = self._root / "bundles"
        out_dir.mkdir()
        stale = "/nix/store/stale00000-removed-driver\n"
        for name in EXPECTED_BUNDLES[:-1]:
            with gzip.open(out_dir / f"{name}.nar.gz", "wb") as stream:
                stream.write(f"existing-{name}\n".encode())
            (out_dir / f"{name}.paths").write_text(fake_path(name) + "\n", encoding="utf-8")
        (out_dir / "vm-drivers.paths").write_text(stale, encoding="utf-8")

        result = self._run("save-missing", str(out_dir), env=env)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        path_info_calls = [
            line for line in nix_log.read_text(encoding="utf-8").splitlines() if line.startswith("path-info -r ")
        ]
        self.assertEqual(len(path_info_calls), 1, path_info_calls)
        self.assertIn(fake_path("vm-drivers"), path_info_calls[0])
        manifest = (out_dir / "bundle-manifest.tsv").read_text(encoding="utf-8")
        self.assertNotIn("stale00000-removed-driver", manifest)
        self.assertIn(f"vm-drivers\t{fake_path('nas-vm-driver')}", manifest)
        driver_export = next(
            line
            for line in nix_store_log.read_text(encoding="utf-8").splitlines()
            if line.startswith("--export") and "nas-vm-driver" in line
        )
        self.assertNotIn("stale00000-removed-driver", driver_export)

    def test_save_enumerates_current_closures_even_when_persisted_paths_exist(self) -> None:
        env, nix_log, _ = self._fake_environment()
        out_dir = self._root / "bundles"
        out_dir.mkdir()
        for name in EXPECTED_BUNDLES:
            (out_dir / f"{name}.paths").write_text("/nix/store/stale00000-removed\n", encoding="utf-8")

        result = self._run("save", str(out_dir), env=env)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        path_info_calls = [
            line for line in nix_log.read_text(encoding="utf-8").splitlines() if line.startswith("path-info -r ")
        ]
        self.assertEqual(len(path_info_calls), len(EXPECTED_BUNDLES), path_info_calls)
        manifest = (out_dir / "bundle-manifest.tsv").read_text(encoding="utf-8")
        self.assertNotIn("stale00000-removed", manifest)
        self.assertIn(f"core\t{fake_path('core')}", manifest)
        self.assertIn(f"identity\t{fake_path('identity')}", manifest)

    def test_manifest_reconstruction_fails_closed_when_an_evaluation_fails(self) -> None:
        env, _, _ = self._fake_environment()
        env["NAS_TEST_FAIL_EVAL"] = "observability"
        out_dir = self._root / "bundles"
        out_dir.mkdir()
        for name in EXPECTED_BUNDLES:
            with gzip.open(out_dir / f"{name}.nar.gz", "wb") as stream:
                stream.write(f"existing-{name}\n".encode())

        result = self._run("save-missing", str(out_dir), env=env)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("evaluation failed", result.stderr)
        self.assertFalse((out_dir / "bundle-manifest.tsv").exists())
        self.assertFalse((out_dir / "bundle-handoff.sha256").exists())

        # A retry with working evaluation must still reconstruct the complete
        # manifest instead of trusting partial state from the failed run.
        env.pop("NAS_TEST_FAIL_EVAL")
        result = self._run("save-missing", str(out_dir), env=env)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        manifest = (out_dir / "bundle-manifest.tsv").read_text(encoding="utf-8")
        self.assertIn(f"observability\t{fake_path('observability')}", manifest)
        self.assertTrue((out_dir / "bundle-handoff.sha256").is_file())

    def test_save_missing_is_a_noop_when_every_archive_exists(self) -> None:
        env, nix_log, nix_store_log = self._fake_environment()
        out_dir = self._root / "bundles"
        out_dir.mkdir()
        for name in EXPECTED_BUNDLES:
            with gzip.open(out_dir / f"{name}.nar.gz", "wb") as stream:
                stream.write(f"existing-{name}\n".encode())
        (out_dir / "bundle-manifest.tsv").write_text(
            "".join(f"{name}\t/nix/store/existing-{name}\n" for name in EXPECTED_BUNDLES),
            encoding="utf-8",
        )

        result = self._run("save-missing", str(out_dir), env=env)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertFalse(nix_log.exists())
        self.assertFalse(nix_store_log.exists())
        for name in EXPECTED_BUNDLES:
            with gzip.open(out_dir / f"{name}.nar.gz", "rb") as stream:
                self.assertEqual(stream.read(), f"existing-{name}\n".encode())

    def test_import_requires_a_directory_argument(self) -> None:
        result = self._run("import")
        self.assertEqual(result.returncode, 1)
        self.assertIn("import requires exactly one directory", result.stderr)


if __name__ == "__main__":
    unittest.main()
