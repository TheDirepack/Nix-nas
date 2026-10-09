from __future__ import annotations

import contextlib
import io
import json
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
SCHEMA = ROOT / "schemas" / "managed-services-v3.schema.json"
if str(SERVICES) not in sys.path:
    sys.path.insert(0, str(SERVICES))

import nas_v2_cli as cli  # noqa: E402


class V2CliTests(unittest.TestCase):
    def test_installed_program_name_is_stable(self) -> None:
        self.assertEqual(cli._parser().prog, "nas-v2")

    def test_default_spec_matches_reconciler_authority_precedence(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "NAS_V2_SPEC": "/legacy/services.yaml",
                "NAS_V2_DESIRED": "/authoritative/services.yaml",
            },
        ):
            self.assertEqual(cli._path_defaults()[0], pathlib.Path("/authoritative/services.yaml"))
            self.assertEqual(
                cli._parser().parse_args(["apply"]).spec,
                pathlib.Path("/authoritative/services.yaml"),
            )
        with mock.patch.dict(os.environ, {"NAS_V2_SPEC": "/legacy/services.yaml"}, clear=True):
            self.assertEqual(cli._path_defaults()[0], pathlib.Path("/legacy/services.yaml"))
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(cli._path_defaults()[0], pathlib.Path("/var/lib/nas-control/services.yaml"))

    def write_spec(self, root: pathlib.Path) -> pathlib.Path:
        path = root / "services.yaml"
        path.write_text(
            """schemaVersion: 3
services:
  demo:
    name: Demo
    workload: {kind: daemon}
    runtime: {type: systemd, unit: demo.service}
""",
            encoding="utf-8",
        )
        return path

    def invoke(self, argv: list[str]) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = cli.main(argv)
        return status, stdout.getvalue(), stderr.getvalue()

    def test_help_does_not_import_compiler_modules(self) -> None:
        with mock.patch.dict(sys.modules, {"nas_v2_apply": None, "nas_v2_spec": None}, clear=False):
            with self.assertRaises(SystemExit) as raised:
                cli.main(["--help"])
        self.assertEqual(raised.exception.code, 0)

    def test_validate_effective_and_plan_are_offline(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            spec = self.write_spec(root)
            for command in ("validate", "effective", "plan"):
                with self.subTest(command=command):
                    status, output, error = self.invoke(
                        [command, "--spec", str(spec), "--schema", str(SCHEMA), "--no-platform"]
                    )
                    self.assertEqual(status, 0, error)
                    self.assertEqual(error, "")
                    value = json.loads(output)
                    if command == "validate":
                        self.assertEqual(value, {"ok": True, "schemaVersion": 3})
                    elif command == "effective":
                        self.assertEqual(value["services"]["demo"]["runtime"]["unit"], "demo.service")
                    else:
                        self.assertEqual(value["runtime"][0]["service"], "demo")

    def test_invalid_input_returns_machine_readable_error_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            spec = root / "bad.yaml"
            spec.write_text("schemaVersion: 3\nservices: [\n", encoding="utf-8")
            output = root / "output.json"
            status, stdout, stderr = self.invoke(
                ["effective", "--spec", str(spec), "--schema", str(SCHEMA), "--no-platform", "--output", str(output)]
            )
            self.assertEqual(status, 2)
            self.assertEqual(stdout, "")
            self.assertEqual(json.loads(stderr)["ok"], False)
            self.assertFalse(output.exists())

    def test_apply_delegates_to_normal_entrypoint(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            spec = self.write_spec(root)
            with mock.patch.object(cli, "_path_defaults", return_value=(spec, SCHEMA, None)):
                with mock.patch("nas_v2_entry.main", return_value=0) as entry:
                    status, output, error = self.invoke(
                        ["apply", "--spec", str(spec), "--schema", str(SCHEMA), "--no-platform"]
                    )
            self.assertEqual(status, 0)
            self.assertEqual(error, "")
            self.assertTrue(json.loads(output)["ok"])
            self.assertEqual(entry.call_count, 1)

    def test_apply_does_not_compile_twice_or_mutate_process_state(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            spec = self.write_spec(root)
            saved_argv = sys.argv
            original_env = os.environ.copy()
            with (
                mock.patch.object(cli, "_compile", side_effect=AssertionError("apply must not precompile")),
                mock.patch("nas_v2_entry.main", return_value=0) as entry,
            ):
                status, _out, err = self.invoke(
                    ["apply", "--spec", str(spec), "--schema", str(SCHEMA), "--no-platform"]
                )
            self.assertEqual(status, 0, err)
            entry.assert_called_once()
            self.assertIs(sys.argv, saved_argv)
            self.assertEqual(os.environ, original_env)

    def test_apply_end_to_end_uses_explicit_options_without_inherited_platform(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            spec = self.write_spec(root)
            output_path = root / "effective.json"
            inherited = {
                "NAS_V2_PLATFORM": str(root / "inherited-platform.json"),
                "NAS_V2_HISTORY_REPOSITORY": str(root / "inherited-history"),
                "NAS_V2_DESIRED": str(root / "inherited-services.yaml"),
            }
            with (
                mock.patch.dict(os.environ, inherited),
                mock.patch("nas_v2_entry._apply_once", return_value={}) as apply_once,
            ):
                original_env = dict(os.environ)
                original_argv = sys.argv
                status, stdout, stderr = self.invoke(
                    [
                        "apply",
                        "--spec",
                        str(spec),
                        "--schema",
                        str(SCHEMA),
                        "--no-platform",
                        "--output",
                        str(output_path),
                        "--git-bin",
                        "git-from-cli",
                    ]
                )
                self.assertEqual(dict(os.environ), original_env)
                self.assertIs(sys.argv, original_argv)
            self.assertEqual(status, 0, stderr)
            self.assertEqual(json.loads(stdout)["ok"], True)
            apply_once.assert_called_once()
            paths = apply_once.call_args.kwargs["paths"]
            self.assertEqual(paths.desired, spec)
            self.assertEqual(paths.schema, SCHEMA)
            self.assertEqual(paths.effective, output_path)
            self.assertEqual(paths.git_bin, "git-from-cli")
            self.assertIsNone(paths.platform)
            self.assertIsNone(paths.history_repository)

    def test_apply_forwards_explicit_history_and_platform_paths(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            spec = self.write_spec(root)
            platform = root / "platform.json"
            platform.write_text("{}\n", encoding="utf-8")
            history = root / "revisions"
            with mock.patch("nas_v2_entry.main", return_value=0) as entry:
                status, _out, err = self.invoke(
                    [
                        "apply",
                        "--spec",
                        str(spec),
                        "--schema",
                        str(SCHEMA),
                        "--platform",
                        str(platform),
                        "--history-repository",
                        str(history),
                    ]
                )
            self.assertEqual(status, 0, err)
            options = entry.call_args.kwargs["overrides"]
            self.assertEqual(options["NAS_V2_PLATFORM"], str(platform))
            self.assertEqual(options["NAS_V2_HISTORY_REPOSITORY"], str(history))

    def test_failed_entry_does_not_claim_apply_succeeded(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            spec = self.write_spec(root)
            with mock.patch("nas_v2_entry.main", return_value=1) as entry:
                status, output, error = self.invoke(
                    ["apply", "--spec", str(spec), "--schema", str(SCHEMA), "--no-platform"]
                )
            self.assertEqual(status, 1, error)
            self.assertEqual(output, "")
            entry.assert_called_once()

    def test_apply_rejects_missing_explicit_platform_without_calling_entry(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            spec = self.write_spec(root)
            with mock.patch("nas_v2_entry.main") as entry:
                status, out, err = self.invoke(
                    [
                        "apply",
                        "--spec",
                        str(spec),
                        "--schema",
                        str(SCHEMA),
                        "--platform",
                        str(root / "missing.json"),
                    ]
                )
            self.assertEqual(status, 2)
            self.assertEqual(out, "")
            self.assertIn("platform capability inventory does not exist", err)
            entry.assert_not_called()


if __name__ == "__main__":
    unittest.main()
