from __future__ import annotations

import json
import os
import pathlib
import re
import shlex
import subprocess
import sys
import tempfile
import textwrap
from types import SimpleNamespace
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "observability-line-protocol.txt"
OBSERVABILITY = ROOT / "modules" / "nas" / "config" / "observability.nix"
SYSTEMD_SERVICES = ROOT / "modules" / "nas" / "config" / "systemd-services.nix"


_FIELD_RE = re.compile(r"^(?P<measurement>[^, ]+)(?:,[^ ]+)? (?P<fields>[^ ]+)(?: [0-9]+)?$")


def numeric_series_from_line_protocol(text: str) -> dict[str, list[float]]:
    """Model the metric names used by VictoriaMetrics' Influx ingestion contract.

    This is deliberately a source-level golden contract, not a replacement for the
    live VM ingestion drill. It catches accidental field/type/name drift before a VM
    is available and the installed-system test verifies the real endpoint later.
    """

    output: dict[str, list[float]] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = _FIELD_RE.fullmatch(line)
        if match is None:
            raise AssertionError(f"Malformed line-protocol fixture: {line}")
        measurement = match.group("measurement")
        for field in match.group("fields").split(","):
            key, raw_value = field.split("=", 1)
            value = raw_value.removesuffix("i").removesuffix("u")
            try:
                number = float(value)
            except ValueError as exc:
                raise AssertionError(
                    f"Golden observability fixture must use numeric fields: {measurement}_{key}={raw_value}"
                ) from exc
            output.setdefault(f"{measurement}_{key}", []).append(number)
    return output


class ObservabilityIngestionContractTests(unittest.TestCase):
    def test_installed_smart_rule_requires_a_wrapper_before_extracting_its_path(self) -> None:
        source = (ROOT / "tests/nixos/integration.nix").read_text()
        snippet = "smart_rule =" + source.split("smart_rule =", 1)[1].split("    smart_command =", 1)[0]
        snippet = textwrap.dedent("    " + snippet)
        wrapper = "/nix/store/0123456789abcdefghijklmnopqrstuv-nas-smartctl-readonly"
        for rule in ("(root) NOPASSWD: " + wrapper, "no matching sudo rule"):
            with self.subTest(rule=rule):
                namespace = {"re": re, "machine": SimpleNamespace(succeed=lambda _command: rule)}
                if rule.startswith("(root)"):
                    exec(snippet, namespace)
                    self.assertEqual(namespace["smart_wrapper"], wrapper)
                else:
                    with self.assertRaisesRegex(AssertionError, "SMART wrapper"):
                        exec(snippet, namespace)

    def run_smart_wrapper(self, arguments: list[str], *, exit_status: int = 0) -> subprocess.CompletedProcess[str]:
        source = OBSERVABILITY.read_text(encoding="utf-8")
        script = source.split("smartctlReadOnly = pkgs.writeShellScript \"nas-smartctl-readonly\" ''", 1)[1].split(
            "\n  '';", 1
        )[0]
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            (root / "bin").mkdir()
            smartctl = root / "bin" / "smartctl"
            smartctl.write_text(
                f"#!{sys.executable}\nimport json, sys\nprint(json.dumps(sys.argv[1:]))\nsys.exit({exit_status})\n",
                encoding="utf-8",
            )
            smartctl.chmod(0o755)
            script = script.replace("${pkgs.smartmontools}", shlex.quote(str(root))).replace("''${", "${")
            self.assertEqual(re.findall(r"\$\{([^}]+)\}", script), ["10"])
            return subprocess.run(
                ["bash", "-c", script, "nas-smartctl-readonly", *arguments],
                text=True,
                capture_output=True,
                check=False,
                env={**os.environ, "LC_ALL": "C"},
            )

    def test_smart_wrapper_accepts_read_only_shapes_and_preserves_arguments(self) -> None:
        base = [
            "--info",
            "--health",
            "--attributes",
            "--tolerance=verypermissive",
            "-n",
            "standby",
            "--format=brief",
            "/dev/sda",
        ]
        for arguments in (
            ["--scan"],
            ["--scan", "--device=nvme"],
            base,
            *[base + ["-d", kind] for kind in ("sat", "sat,12", "sntjmicron/sat", "sntasmedia/sat", "megaraid,0")],
        ):
            with self.subTest(arguments=arguments):
                result = self.run_smart_wrapper(arguments)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), arguments)

    def test_smart_wrapper_rejects_mutating_or_malformed_commands_before_exec(self) -> None:
        base = [
            "--info",
            "--health",
            "--attributes",
            "--tolerance=verypermissive",
            "-n",
            "standby",
            "--format=brief",
            "/dev/sda",
        ]
        for arguments in (
            [],
            ["--scan", "--device=ata"],
            ["--set=on", "/dev/sda"],
            base + ["-d"],
            base + ["-d", "sat", "--set=on"],
            *[base + ["-d", kind] for kind in ("", "sat;id", "sat\n--set=on", "sat --set=on", "$(id)")],
            base[:-1] + ["/etc/passwd"],
            base[:-1] + ["/dev/../etc/passwd"],
        ):
            with self.subTest(arguments=arguments):
                result = self.run_smart_wrapper(arguments)
                self.assertEqual(result.returncode, 64, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertIn("refused SMART command", result.stderr)

    def test_smart_wrapper_preserves_smartctl_health_exit_status(self) -> None:
        result = self.run_smart_wrapper(["--scan"], exit_status=8)
        self.assertEqual(result.returncode, 8)

    def test_alert_and_dashboard_metric_names_exist_in_golden_ingestion_shape(self) -> None:
        series = numeric_series_from_line_protocol(FIXTURE.read_text(encoding="utf-8"))
        source = OBSERVABILITY.read_text(encoding="utf-8")
        expected = {
            "system_uptime",
            "cpu_usage_active",
            "disk_used_percent",
            "systemd_units_active_code",
            "smart_device_health_ok",
            "smart_device_temp_c",
        }
        self.assertTrue(expected.issubset(series), expected - set(series))
        for metric in expected:
            self.assertIn(metric, source)

    def test_smart_health_golden_fixture_preserves_both_numeric_states(self) -> None:
        series = numeric_series_from_line_protocol(FIXTURE.read_text(encoding="utf-8"))
        self.assertEqual(set(series["smart_device_health_ok"]), {0.0, 1.0})
        source = OBSERVABILITY.read_text(encoding="utf-8")
        self.assertIn('fields.float = [ "health_ok" ];', source)
        self.assertIn("smart_device_health_ok == 0", source)

    def test_fixture_covers_optional_ups_and_zfs_collection_shapes(self) -> None:
        series = numeric_series_from_line_protocol(FIXTURE.read_text(encoding="utf-8"))
        self.assertIn("zfs_arc_size", series)
        self.assertIn("upsd_load_percent", series)
        self.assertIn("upsd_battery_charge", series)

    def test_grafana_service_can_traverse_the_private_observability_secret_directory(self) -> None:
        source = SYSTEMD_SERVICES.read_text(encoding="utf-8")
        grafana = source.split("grafana = lib.mkIf", 1)[1].split("victoriametrics = lib.mkIf", 1)[0]

        self.assertIn('SupplementaryGroups = [ "nas-observability" ];', grafana)


if __name__ == "__main__":
    unittest.main()
