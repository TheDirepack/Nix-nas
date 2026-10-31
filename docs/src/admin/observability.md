# Observability and alerts

The observability path is:

```text
Telegraf -> VictoriaMetrics -> vmalert -> Alertmanager -> optional alertmanager-ntfy -> ntfy
                         \-> optional Grafana
```

## Metrics collection and storage

Telegraf collects host CPU, memory, filesystems, disk I/O, processes, kernel, systemd units, ZFS, SMART, and optional NUT UPS metrics. It writes directly to the loopback VictoriaMetrics endpoint.

Single-node VictoriaMetrics stores the time-series data and provides the PromQL and MetricsQL query endpoint. Configure retention and ports with `nas.observability.*`. Use `/victoriametrics/` for VMUI and API inspection.

Telegraf normally runs unprivileged. SMART collection is the deliberate exception. The `telegraf` account may invoke only the immutable Nix-store `nas-smartctl-readonly` wrapper through the installed sudo rule. That wrapper permits device discovery and fixed read-only SMART queries, not arbitrary `smartctl` options. Telegraf resolves sudo through NixOS's privileged `/run/wrappers/bin/sudo` wrapper.

## Dashboards

Grafana is optional and can run on demand. Its declarative VictoriaMetrics datasource points directly to the local VictoriaMetrics service. Nix generates the baseline dashboards. Dashboards created in the Grafana UI remain in Grafana's mutable state.

## Alerts

`vmalert` evaluates NAS rules against VictoriaMetrics and sends firing and resolved alerts to Alertmanager. Alertmanager owns grouping, deduplication, inhibition, repeat timing, and the `/alerts/` status interface.

The current routing policy groups by the complete alert label set, sends a new group immediately, allows updates to a group once per minute, and repeats unresolved alerts every four hours. Inhibition is limited to two pairs:

- `NasFilesystemCriticalSpace` suppresses `NasFilesystemLowSpace` only for matching `host` and `path` labels.
- `NasSmartHealthFailed` suppresses `NasDiskTemperatureHigh` only for matching `host` and `device` labels.

Other alert pairs do not inhibit one another. `NasTelemetryStale` requires no `system_uptime` samples in the preceding three minutes, followed by a two-minute firing delay.

When ntfy is enabled, Alertmanager sends its webhook notifications to `alertmanager-ntfy`. The bridge authenticates to the loopback ntfy service with runtime-only credentials rendered from the activated NAS secrets.

`ntfy-sh.service` waits for its loopback health endpoint before completing startup,
so health-failure notifications ordered after it do not race the HTTP listener.
The readiness check is bounded to 15 seconds; failure remains visible in systemd.
It does not clear failed units or retry notification publication.

- **Alerts/status:** `/alerts/`
- **Grafana:** `/metrics/`
- **VictoriaMetrics:** `/victoriametrics/`
- **Notifications:** `/notifications/`

There is no separate NAS alert-router database or custom deduplication state. Alertmanager owns alert-routing state, and ntfy owns notification-server state.

## What to check when telemetry looks wrong

1. Open **NAS Overview** and check failed services.
2. Inspect `telegraf.service`, `victoriametrics.service`, `vmalert-nas.service`, and `alertmanager.service` when alerting is enabled.
3. Use VictoriaMetrics VMUI to confirm recent `system_uptime` samples exist.
4. Check `/alerts/` for Alertmanager state.
5. If only push notifications are missing, inspect `alertmanager-ntfy.service` and `ntfy-sh.service` separately from metric ingestion and rule evaluation.

The external observability drill writes a synthetic metric, queries it back, checks vmalert and Alertmanager, and verifies ntfy delivery when notifications are enabled.
