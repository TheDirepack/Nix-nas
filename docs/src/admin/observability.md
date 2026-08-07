# Observability and alerts

The default observability path is intentionally small:

```text
Telegraf → VictoriaMetrics → vmalert → NAS alert router → optional ntfy
                         ↘ optional Grafana
```

## Metrics collection and storage

Telegraf collects host CPU, memory, filesystems, disk I/O, processes, kernel, systemd units, ZFS, SMART, and optional NUT UPS metrics. It writes directly to the loopback VictoriaMetrics endpoint.

Single-node VictoriaMetrics is the time-series database and PromQL/MetricsQL query endpoint. Configure retention and ports with `nas.observability.*`; use `/victoriametrics/` for VMUI/API inspection.

Telegraf normally runs unprivileged. SMART collection is the deliberate exception: the `telegraf` account may run only the immutable Nix-store `smartctl` path through the exact sudo rule installed by the module.

## Dashboards

Grafana is optional and can run on demand. Its declarative VictoriaMetrics datasource points directly to the local VictoriaMetrics service. Baseline dashboards are generated from Nix; dashboards created in the Grafana UI remain in Grafana's mutable state.

## Alerts

`vmalert` evaluates NAS rules against VictoriaMetrics. The `nas-alert-router` receives those notifications, applies bounded deduplication and critical-over-warning inhibition, keeps a small status record, and sends to ntfy when notifications are enabled.

- **Alerts/status:** `/alerts/`
- **Grafana:** `/metrics/`
- **VictoriaMetrics:** `/victoriametrics/`
- **Notifications:** `/notifications/`

The alert router is not a second general alert-management UI. Change thresholds and routing behavior declaratively. Its delivery contract is intentionally smaller than Alertmanager:

- notification delivery is **at least once**, not exactly once; a crash after ntfy accepts a message but before the local state commit can produce a duplicate;
- successful deliveries are persisted before later alerts in the same batch are attempted, so a partial downstream outage does not erase earlier success;
- unresolved downstream failures remain failures and are eligible for a later vmalert delivery attempt; there is no independent durable notification queue;
- deduplication is a bounded repeat window and inhibition is limited to the explicitly implemented critical-over-warning rule;
- silences, HA clustering, arbitrary grouping/routing trees, and the rest of Alertmanager's policy surface are intentionally out of scope.

## What to check when telemetry looks wrong

1. Open **NAS Overview** and check failed services.
2. Inspect `telegraf.service`, `victoriametrics.service`, and, when alerting is enabled, the vmalert/router units.
3. Use VictoriaMetrics VMUI to confirm recent `system_uptime` samples exist.
4. Check `/alerts/` for rule evaluation/delivery state.
5. If only notifications are missing, check ntfy separately from metric ingestion and rule evaluation.

The external observability drill writes a synthetic metric, queries it back, checks vmalert, submits a temporary notification to the router, and verifies ntfy when enabled.
