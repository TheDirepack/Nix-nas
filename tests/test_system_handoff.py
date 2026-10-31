from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile
import textwrap
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "system-handoff.sh"


class SystemHandoffTests(unittest.TestCase):
    def write_executable(self, path: pathlib.Path, source: str) -> None:
        path.write_text(textwrap.dedent(source).lstrip(), encoding="utf-8")
        path.chmod(0o755)

    def make_tools(self, root: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
        fake_nix = root / "fake-nix"
        fake_store = root / "fake-nix-store"
        self.write_executable(
            fake_nix,
            r"""
            #!/usr/bin/env bash
            set -euo pipefail
            case "${1:-}" in
              build)
                exit 0
                ;;
              eval)
                ref=${3:-}
                case "$ref" in
                  *nas-ci-ready*) printf '/nix/store/ci-root' ;;
                  *nas-qemu*) printf '/nix/store/qemu-root' ;;
                  *) exit 2 ;;
                esac
                ;;
              path-info)
                if [[ "${2:-}" == "-r" ]]; then
                  printf '%s\n' \
                    /nix/store/base-a \
                    /nix/store/base-b \
                    /nix/store/ci-root \
                    /nix/store/qemu-root \
                    /nix/store/system-only
                  if [[ -n "${FAKE_EXTRA_PATHS_FILE:-}" ]]; then
                    cat -- "$FAKE_EXTRA_PATHS_FILE"
                  fi
                else
                  shift
                  for path in "$@"; do
                    grep -Fxq -- "$path" "${FAKE_IMPORTED_PATHS:?}" || exit 92
                  done
                fi
                ;;
              *)
                exit 2
                ;;
            esac
            """,
        )
        self.write_executable(
            fake_store,
            r"""
            #!/usr/bin/env bash
            set -euo pipefail
            case "${1:-}" in
              --query)
                [[ "${2:-}" == "--requisites" ]] || exit 2
                # A non-alphabetical dependency-first ordering is deliberate.
                printf '%s\n' \
                  /nix/store/base-a \
                  /nix/store/base-b \
                  /nix/store/qemu-root \
                  /nix/store/system-only \
                  /nix/store/ci-root
                if [[ -n "${FAKE_EXTRA_PATHS_FILE:-}" ]]; then
                  cat -- "$FAKE_EXTRA_PATHS_FILE"
                fi
                ;;
              --export)
                shift
                printf '%s\n' "$@" >> "${FAKE_EXPORT_LOG:?}"
                printf 'export:%s\n' "$#" >> "${FAKE_EXPORT_CALLS:?}"
                printf 'fake-nix-export\n'
                printf '%s\n' "$@"
                printf 'fake-nix-end\n'
                ;;
              --import)
                mapfile -t content
                [[ "${content[0]:-}" == "fake-nix-export" ]] || exit 91
                [[ "${content[-1]:-}" == "fake-nix-end" ]] || exit 91
                for ((i=1; i<${#content[@]}-1; i++)); do
                  if [[ "${content[i]}" != "${FAKE_OMIT_IMPORTED_PATH:-}" ]]; then
                    printf '%s\n' "${content[i]}" >> "${FAKE_IMPORTED_PATHS:?}"
                  fi
                done
                printf 'import\n' >> "${FAKE_IMPORT_LOG:?}"
                ;;
              *)
                exit 2
                ;;
            esac
            """,
        )
        return fake_nix, fake_store

    def environment(
        self,
        fake_nix: pathlib.Path,
        fake_store: pathlib.Path,
        export_log: pathlib.Path,
    ) -> dict[str, str]:
        env = os.environ.copy()
        env.update(
            {
                "NAS_SYSTEM_HANDOFF_NIX": str(fake_nix),
                "NAS_SYSTEM_HANDOFF_NIX_STORE": str(fake_store),
                "FAKE_EXPORT_LOG": str(export_log),
                "FAKE_EXPORT_CALLS": str(export_log.parent / "export-calls.log"),
                "FAKE_IMPORT_LOG": str(export_log.parent / "import-calls.log"),
                "FAKE_IMPORTED_PATHS": str(export_log.parent / "imported-paths.log"),
            }
        )
        return env

    def run_handoff(
        self,
        command: str,
        handoff: pathlib.Path,
        env: dict[str, str],
        *,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(SCRIPT), command, str(handoff)],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=check,
        )

    def rewrite_checksum(self, handoff: pathlib.Path) -> None:
        exports = (handoff / "system-closures.exports").read_text(encoding="utf-8").splitlines()
        result = subprocess.run(
            [
                "sha256sum",
                "system-closures.paths",
                "system-closures.delta.paths",
                "bundle-manifest.tsv",
                "system-closures.exports",
                "system-closures.delta.import-order",
                *exports,
            ],
            cwd=handoff,
            text=True,
            capture_output=True,
            check=True,
        )
        (handoff / "system-closures.sha256").write_text(
            result.stdout,
            encoding="utf-8",
        )

    def test_save_exports_only_paths_not_already_in_reusable_bundles(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            handoff = root / "handoff"
            handoff.mkdir()
            (handoff / "bundle-manifest.tsv").write_text(
                "core\t/nix/store/base-a\nidentity\t/nix/store/base-b\n",
                encoding="utf-8",
            )
            export_log = root / "export.log"
            fake_nix, fake_store = self.make_tools(root)
            env = self.environment(fake_nix, fake_store, export_log)

            self.run_handoff("save", handoff, env)

            full_paths = (handoff / "system-closures.paths").read_text(encoding="utf-8").splitlines()
            delta_paths = (handoff / "system-closures.delta.paths").read_text(encoding="utf-8").splitlines()
            exported = export_log.read_text(encoding="utf-8").splitlines()

            self.assertEqual(
                full_paths,
                [
                    "/nix/store/base-a",
                    "/nix/store/base-b",
                    "/nix/store/ci-root",
                    "/nix/store/qemu-root",
                    "/nix/store/system-only",
                ],
            )
            self.assertEqual(
                delta_paths,
                [
                    "/nix/store/ci-root",
                    "/nix/store/qemu-root",
                    "/nix/store/system-only",
                ],
            )
            order = (handoff / "system-closures.delta.import-order").read_text(encoding="utf-8").splitlines()
            self.assertEqual(exported, order)
            self.assertEqual(sorted(exported), delta_paths)
            self.assertNotEqual(exported, delta_paths)
            self.run_handoff("verify", handoff, env)

            # Simulate other reusable archives present in the complete transport.
            (handoff / "core.nar.gz").write_bytes(b"transport")
            self.run_handoff("import", handoff, env)
            self.assertFalse(any(handoff.glob("*.nar.gz")))

    def test_large_delta_has_complete_independent_export_and_import_streams(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            handoff = root / "handoff"
            handoff.mkdir()
            (handoff / "bundle-manifest.tsv").write_text(
                "core\t/nix/store/base-a\nidentity\t/nix/store/base-b\n",
                encoding="utf-8",
            )
            extra = root / "extra-paths.txt"
            extra.write_text(
                "".join(f"/nix/store/test-{index:04d}\n" for index in range(260)),
                encoding="utf-8",
            )
            export_log = root / "export.log"
            fake_nix, fake_store = self.make_tools(root)
            env = self.environment(fake_nix, fake_store, export_log)
            env["FAKE_EXTRA_PATHS_FILE"] = str(extra)
            self.run_handoff("save", handoff, env)
            exports = (handoff / "system-closures.exports").read_text(encoding="utf-8").splitlines()
            self.assertEqual(
                exports,
                [
                    "system-closures.nar.gz",
                    "system-closures.part-000001.nar.gz",
                    "system-closures.part-000002.nar.gz",
                ],
            )
            self.assertEqual(
                (root / "export-calls.log").read_text(encoding="utf-8").splitlines(),
                ["export:128", "export:128", "export:7"],
            )
            self.assertEqual(
                export_log.read_text(encoding="utf-8").splitlines(),
                (handoff / "system-closures.delta.import-order").read_text(encoding="utf-8").splitlines(),
            )
            self.run_handoff("verify", handoff, env)
            self.run_handoff("import", handoff, env)
            self.assertEqual(
                (root / "import-calls.log").read_text(encoding="utf-8").splitlines(),
                ["import", "import", "import"],
            )
            self.assertFalse(list(handoff.glob("*.nar.gz")))

    def test_import_keeps_archives_when_a_promised_store_path_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            handoff = root / "handoff"
            handoff.mkdir()
            (handoff / "bundle-manifest.tsv").write_text(
                "core\t/nix/store/base-a\nidentity\t/nix/store/base-b\n",
                encoding="utf-8",
            )
            export_log = root / "export.log"
            fake_nix, fake_store = self.make_tools(root)
            env = self.environment(fake_nix, fake_store, export_log)
            env["FAKE_OMIT_IMPORTED_PATH"] = "/nix/store/qemu-root"
            self.run_handoff("save", handoff, env)
            failed = self.run_handoff("import", handoff, env, check=False)
            self.assertNotEqual(failed.returncode, 0)
            self.assertTrue((handoff / "system-closures.nar.gz").exists())
            self.assertIn("system-only", (root / "imported-paths.log").read_text(encoding="utf-8"))

    def test_verify_rejects_missing_shard_checksum_even_with_valid_other_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            handoff = root / "handoff"
            handoff.mkdir()
            (handoff / "bundle-manifest.tsv").write_text(
                "core\t/nix/store/base-a\nidentity\t/nix/store/base-b\n",
                encoding="utf-8",
            )
            extra = root / "extra-paths.txt"
            extra.write_text(
                "".join(f"/nix/store/test-{index:04d}\n" for index in range(140)),
                encoding="utf-8",
            )
            export_log = root / "export.log"
            fake_nix, fake_store = self.make_tools(root)
            env = self.environment(fake_nix, fake_store, export_log)
            env["FAKE_EXTRA_PATHS_FILE"] = str(extra)
            self.run_handoff("save", handoff, env)
            checksum = handoff / "system-closures.sha256"
            checksum.write_text(
                "".join(
                    line for line in checksum.read_text(encoding="utf-8").splitlines(keepends=True)
                    if "system-closures.part-000001.nar.gz" not in line
                ),
                encoding="utf-8",
            )
            failed = self.run_handoff("verify", handoff, env, check=False)
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn("missing checksum entry", failed.stderr)

    def test_verify_rejects_missing_or_out_of_order_export_shards(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            handoff = root / "handoff"
            handoff.mkdir()
            (handoff / "bundle-manifest.tsv").write_text(
                "core\t/nix/store/base-a\nidentity\t/nix/store/base-b\n",
                encoding="utf-8",
            )
            export_log = root / "export.log"
            fake_nix, fake_store = self.make_tools(root)
            env = self.environment(fake_nix, fake_store, export_log)
            self.run_handoff("save", handoff, env)
            (handoff / "system-closures.exports").write_text(
                "system-closures.part-000001.nar.gz\n", encoding="utf-8"
            )
            invalid = self.run_handoff("verify", handoff, env, check=False)
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn("missing or out-of-order export stream", invalid.stderr)

    def test_fully_covered_reusable_bundles_need_no_store_export(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            handoff = root / "handoff"
            handoff.mkdir()
            full = (
                "/nix/store/base-a",
                "/nix/store/base-b",
                "/nix/store/ci-root",
                "/nix/store/qemu-root",
                "/nix/store/system-only",
            )
            (handoff / "bundle-manifest.tsv").write_text(
                "".join(f"bundle\t{path}\n" for path in full),
                encoding="utf-8",
            )
            export_log = root / "export.log"
            fake_nix, fake_store = self.make_tools(root)
            env = self.environment(fake_nix, fake_store, export_log)
            self.run_handoff("save", handoff, env)
            self.assertEqual((handoff / "system-closures.delta.paths").read_text(), "")
            self.assertEqual((handoff / "system-closures.delta.import-order").read_text(), "")
            self.assertEqual(
                (handoff / "system-closures.exports").read_text().splitlines(),
                ["system-closures.nar.gz"],
            )
            self.assertFalse((root / "export-calls.log").exists())
            self.run_handoff("verify", handoff, env)
            self.run_handoff("import", handoff, env)
            self.assertFalse((root / "import-calls.log").exists())

    def test_verify_rejects_delta_that_duplicates_bundle_transport(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            handoff = root / "handoff"
            handoff.mkdir()
            (handoff / "bundle-manifest.tsv").write_text(
                "core\t/nix/store/base-a\nidentity\t/nix/store/base-b\n",
                encoding="utf-8",
            )
            export_log = root / "export.log"
            fake_nix, fake_store = self.make_tools(root)
            env = self.environment(fake_nix, fake_store, export_log)
            self.run_handoff("save", handoff, env)

            delta = handoff / "system-closures.delta.paths"
            paths = delta.read_text(encoding="utf-8").splitlines()
            paths.append("/nix/store/base-a")
            delta.write_text("\n".join(sorted(paths)) + "\n", encoding="utf-8")
            self.rewrite_checksum(handoff)

            result = self.run_handoff("verify", handoff, env, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("delta duplicates reusable bundle path", result.stderr)


if __name__ == "__main__":
    unittest.main()
