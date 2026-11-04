from __future__ import annotations

import gzip
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

            # Fixture reference graph. Test extras model closure reachable only
            # through the aggregate root, so the full path list is exactly the
            # requisites closure of the two system roots.
            declare -A dependencies=(
              [/nix/store/base-a]=""
              [/nix/store/base-b]=""
              [/nix/store/qemu-root]=/nix/store/base-a
              [/nix/store/system-only]=/nix/store/base-b
            )
            extras=""
            if [[ -n "${FAKE_EXTRA_PATHS_FILE:-}" ]]; then
              extras=$(tr '\n' ' ' < "$FAKE_EXTRA_PATHS_FILE")
            fi
            dependencies[/nix/store/ci-root]="${extras}/nix/store/qemu-root /nix/store/system-only"

            declare -A collected=()

            collect_requisites() {
              local path=$1 reference
              if [[ -n "${collected[$path]+present}" ]]; then
                return 0
              fi
              collected["$path"]=1
              for reference in ${dependencies[$path]:-}; do
                collect_requisites "$reference"
              done
              printf '%s\n' "$path"
            }

            case "${1:-}" in
              --query)
                [[ "${2:-}" == "--requisites" ]] || exit 2
                shift 2
                collected=()
                if [[ -n "${FAKE_REQUISITES_UNSORTED:-}" ]]; then
                  # Simulate a requisites implementation whose output is not
                  # dependency-first: requesters precede their requisites.
                  printf '%s\n' "$@"
                fi
                for path in "$@"; do
                  collect_requisites "$path"
                done
                ;;
              --export)
                shift
                count=0
                if [[ -f "${FAKE_EXPORT_CALLS:?}" ]]; then
                  count=$(wc -l < "$FAKE_EXPORT_CALLS")
                fi
                index=$((count + 1))
                printf '%s\n' "$@" >> "${FAKE_EXPORT_LOG:?}"
                printf 'export:%s\n' "$#" >> "$FAKE_EXPORT_CALLS"
                printf 'fake-nix-export %s\n' "$index"
                printf '%s\n' "$@"
                printf 'fake-nix-end %s\n' "$index"
                ;;
              --import)
                mapfile -t content
                ((${#content[@]} >= 2)) || exit 91
                [[ "${content[0]}" =~ ^fake-nix-export\ ([0-9]+)$ ]] || exit 91
                index=${BASH_REMATCH[1]}
                [[ "${content[-1]}" == "fake-nix-end $index" ]] || exit 91
                imported=0
                # Exactly one start marker and one end marker per import call:
                # an interior marker means export streams were concatenated.
                for ((i=1; i<${#content[@]}-1; i++)); do
                  if [[ "${content[i]}" =~ ^fake-nix-(export|end) ]]; then
                    exit 91
                  fi
                  if [[ "${content[i]}" != "${FAKE_OMIT_IMPORTED_PATH:-}" ]]; then
                    printf '%s\n' "${content[i]}" >> "${FAKE_IMPORTED_PATHS:?}"
                    imported=$((imported + 1))
                  fi
                done
                printf '%s\t%s\n' "$index" "$imported" >> "${FAKE_IMPORT_LOG:?}"
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

    def export_shards(self, root: pathlib.Path) -> list[list[str]]:
        counts = [
            int(line.split(":", 1)[1]) for line in (root / "export-calls.log").read_text(encoding="utf-8").splitlines()
        ]
        exported = (root / "export.log").read_text(encoding="utf-8").splitlines()
        shards: list[list[str]] = []
        offset = 0
        for count in counts:
            shards.append(exported[offset : offset + count])
            offset += count
        self.assertEqual(offset, len(exported))
        return shards

    def import_shards(self, root: pathlib.Path) -> list[tuple[str, list[str]]]:
        records = [line.split("\t") for line in (root / "import-calls.log").read_text(encoding="utf-8").splitlines()]
        imported = (root / "imported-paths.log").read_text(encoding="utf-8").splitlines()
        shards: list[tuple[str, list[str]]] = []
        offset = 0
        for index, count in records:
            count = int(count)
            shards.append((index, imported[offset : offset + count]))
            offset += count
        self.assertEqual(offset, len(imported))
        return shards

    def assert_import_matches_export(self, root: pathlib.Path) -> None:
        export_shards = self.export_shards(root)
        import_shards = self.import_shards(root)
        self.assertEqual(len(import_shards), len(export_shards))
        for position, ((index, paths), expected) in enumerate(zip(import_shards, export_shards), start=1):
            self.assertEqual(index, str(position), "import opened the wrong shard archive")
            self.assertEqual(paths, expected)

    def fixture_dependencies(self, extras: tuple[str, ...] = ()) -> dict[str, tuple[str, ...]]:
        dependencies = {
            "/nix/store/base-a": (),
            "/nix/store/base-b": (),
            "/nix/store/qemu-root": ("/nix/store/base-a",),
            "/nix/store/system-only": ("/nix/store/base-b",),
            "/nix/store/ci-root": ("/nix/store/qemu-root", "/nix/store/system-only", *extras),
        }
        for path in extras:
            dependencies[path] = ()
        return dependencies

    def assert_shards_are_dependency_closed(
        self,
        shards: list[list[str]],
        bundles: tuple[str, ...],
        dependencies: dict[str, tuple[str, ...]],
    ) -> None:
        available = set(bundles)
        for shard in shards:
            paths = set(shard)
            for path in shard:
                missing = set(dependencies.get(path, ())) - available - paths
                self.assertEqual(missing, set(), f"shard omits requisites of {path}: {sorted(missing)}")
            available |= paths

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
            self.assertFalse(list(handoff.glob("system-closures.delta.import-order.*")))

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
            self.assertEqual(
                exported,
                [
                    "/nix/store/qemu-root",
                    "/nix/store/system-only",
                    "/nix/store/ci-root",
                ],
            )
            self.assertEqual(sorted(exported), delta_paths)
            self.assertNotEqual(exported, delta_paths)
            self.assert_shards_are_dependency_closed(
                self.export_shards(root),
                ("/nix/store/base-a", "/nix/store/base-b"),
                self.fixture_dependencies(),
            )
            self.run_handoff("verify", handoff, env)

            # Simulate other reusable archives present in the complete transport.
            (handoff / "core.nar.gz").write_bytes(b"transport")
            self.run_handoff("import", handoff, env)
            self.assert_import_matches_export(root)
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
            extras = tuple(f"/nix/store/test-{index:04d}" for index in range(260))
            extra = root / "extra-paths.txt"
            extra.write_text("".join(f"{path}\n" for path in extras), encoding="utf-8")
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
            self.assert_shards_are_dependency_closed(
                self.export_shards(root),
                ("/nix/store/base-a", "/nix/store/base-b"),
                self.fixture_dependencies(extras),
            )
            self.run_handoff("verify", handoff, env)
            self.run_handoff("import", handoff, env)
            self.assertEqual(
                (root / "import-calls.log").read_text(encoding="utf-8").splitlines(),
                ["1\t128", "2\t128", "3\t7"],
            )
            # Every manifest entry must open its own shard archive: a repeated
            # first shard changes the recorded stream marker and the paths.
            self.assert_import_matches_export(root)
            imported = (root / "imported-paths.log").read_text(encoding="utf-8").splitlines()
            delta_paths = (handoff / "system-closures.delta.paths").read_text(encoding="utf-8").splitlines()
            self.assertEqual(set(imported), set(delta_paths))
            self.assertEqual(len(imported), len(delta_paths))
            self.assertFalse(list(handoff.glob("*.nar.gz")))

    def test_save_pulls_requisites_that_would_land_in_a_later_shard(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            handoff = root / "handoff"
            handoff.mkdir()
            (handoff / "bundle-manifest.tsv").write_text(
                "core\t/nix/store/base-a\nidentity\t/nix/store/base-b\n",
                encoding="utf-8",
            )
            extras = tuple(f"/nix/store/test-{index:04d}" for index in range(260))
            extra = root / "extra-paths.txt"
            extra.write_text("".join(f"{path}\n" for path in extras), encoding="utf-8")
            export_log = root / "export.log"
            fake_nix, fake_store = self.make_tools(root)
            env = self.environment(fake_nix, fake_store, export_log)
            env["FAKE_EXTRA_PATHS_FILE"] = str(extra)
            # Requisites arrive requester-first, so the shard planning must move
            # the aggregate root's requisites into its own shard.
            env["FAKE_REQUISITES_UNSORTED"] = "1"
            self.run_handoff("save", handoff, env)

            shards = self.export_shards(root)
            self.assert_shards_are_dependency_closed(
                shards,
                ("/nix/store/base-a", "/nix/store/base-b"),
                self.fixture_dependencies(extras),
            )
            shard_of = {path: position for position, shard in enumerate(shards, start=1) for path in shard}
            for requisite in ("/nix/store/qemu-root", "/nix/store/system-only", *extras):
                self.assertLessEqual(shard_of[requisite], shard_of["/nix/store/ci-root"])
            self.run_handoff("verify", handoff, env)
            self.run_handoff("import", handoff, env)
            self.assert_import_matches_export(root)
            delta_paths = (handoff / "system-closures.delta.paths").read_text(encoding="utf-8").splitlines()
            self.assertEqual(
                set((root / "imported-paths.log").read_text(encoding="utf-8").splitlines()),
                set(delta_paths),
            )

    def test_import_rejects_concatenated_export_stream(self) -> None:
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

            # A concatenated archive carries two complete export payloads back
            # to back, so every promised path is present and only the interior
            # stream marker can reject it.
            stream = (
                b"fake-nix-export 1\n/nix/store/qemu-root\n/nix/store/system-only\n/nix/store/ci-root\nfake-nix-end 1\n"
            )
            archive = handoff / "system-closures.nar.gz"
            archive.write_bytes(gzip.compress(stream + stream))
            self.rewrite_checksum(handoff)

            failed = self.run_handoff("import", handoff, env, check=False)
            self.assertNotEqual(failed.returncode, 0)
            self.assertFalse((root / "import-calls.log").exists())

    def test_repeated_first_shard_transport_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            handoff = root / "handoff"
            handoff.mkdir()
            (handoff / "bundle-manifest.tsv").write_text(
                "core\t/nix/store/base-a\nidentity\t/nix/store/base-b\n",
                encoding="utf-8",
            )
            extras = tuple(f"/nix/store/test-{index:04d}" for index in range(260))
            extra = root / "extra-paths.txt"
            extra.write_text("".join(f"{path}\n" for path in extras), encoding="utf-8")
            export_log = root / "export.log"
            fake_nix, fake_store = self.make_tools(root)
            env = self.environment(fake_nix, fake_store, export_log)
            env["FAKE_EXTRA_PATHS_FILE"] = str(extra)
            self.run_handoff("save", handoff, env)

            # Transport corruption: every later manifest entry now carries the
            # first shard's bytes, so a repeated-first-shard import is visible.
            first = (handoff / "system-closures.nar.gz").read_bytes()
            for name in ("system-closures.part-000001.nar.gz", "system-closures.part-000002.nar.gz"):
                (handoff / name).write_bytes(first)
            self.rewrite_checksum(handoff)

            failed = self.run_handoff("import", handoff, env, check=False)
            self.assertNotEqual(failed.returncode, 0)
            self.assertTrue((handoff / "system-closures.nar.gz").exists())
            records = (root / "import-calls.log").read_text(encoding="utf-8").splitlines()
            self.assertEqual([record.split("\t")[0] for record in records], ["1", "1", "1"])
            with self.assertRaises(AssertionError):
                self.assert_import_matches_export(root)

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
                    line
                    for line in checksum.read_text(encoding="utf-8").splitlines(keepends=True)
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
            (handoff / "system-closures.exports").write_text("system-closures.part-000001.nar.gz\n", encoding="utf-8")
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
            order = handoff / "system-closures.delta.import-order"
            order.write_text("/nix/store/base-a\n" + order.read_text(encoding="utf-8"), encoding="utf-8")
            self.rewrite_checksum(handoff)

            result = self.run_handoff("verify", handoff, env, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("delta duplicates reusable bundle path", result.stderr)


if __name__ == "__main__":
    unittest.main()
