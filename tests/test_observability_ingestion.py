from __future__ import annotations

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "observability-line-protocol.txt"
OBSERVABILITY = ROOT / "modules" / "nas" / "config" / "observability.nix"


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


if __name__ == "__main__":
    unittest.main()
