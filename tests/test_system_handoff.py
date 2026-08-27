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
                printf '%s\n' \
                  /nix/store/base-a \
                  /nix/store/base-b \
                  /nix/store/ci-root \
                  /nix/store/qemu-root \
                  /nix/store/system-only
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
              --export)
                shift
                printf '%s\n' "$@" >> "${FAKE_EXPORT_LOG:?}"
                printf 'fake-nix-export\n'
                ;;
              --import)
                cat >/dev/null
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
        result = subprocess.run(
            [
                "sha256sum",
                "system-closures.nar.gz",
                "system-closures.paths",
                "system-closures.delta.paths",
                "bundle-manifest.tsv",
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
            self.assertEqual(exported, delta_paths)
            self.run_handoff("verify", handoff, env)

            # Simulate other reusable archives present in the complete transport.
            (handoff / "core.nar.gz").write_bytes(b"transport")
            self.run_handoff("import", handoff, env)
            self.assertFalse(any(handoff.glob("*.nar.gz")))

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
