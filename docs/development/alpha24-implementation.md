# Alpha.24 implementation record

This record describes source changes made from the supplied `2.1.0-alpha.23-source-only-unverified` tree. It is not release qualification evidence.

## Implemented

### Central capability policy

- Added `modules/nas/internal/capability-registry.nix` as the declarative source for capability IDs, allow/deny groups, descriptions, owning routes, administrator bypass, wake behavior, setup/Cockpit visibility, and Authentik claims.
- Added a closed JSON Schema for the exported registry.
- Changed Caddy route generation to resolve capabilities through the registry and fail evaluation for unknown IDs.
- Changed Python policy loading to validate the generated registry and reject malformed IDs, groups, booleans, duplicates, and mismatched reserved identity groups.
- Exported the same registry through the installed system data and documentation paths.

### Operations and hardening

- Added `nas_logging.py`, a bounded JSON logging helper with stable operation fields and recursive secret-key redaction.
- Added a root-service audit documenting current privilege boundaries and remaining review work.
- Removed Telegraf's unused inherited `CAP_NET_RAW`; SMART collection retains one exact passwordless `smartctl` rule and does not use broad root execution.
- Corrected the scheduler backend comparison from the nonexistent `cockpit` value to `cockpit-scheduler`.

### VictoriaMetrics-only observability

- Retained single-node VictoriaMetrics as the only metrics store.
- Replaced the Prometheus node, SMART, and NUT exporter services with one Telegraf process.
- Configured Telegraf to collect host, filesystem, disk I/O, kernel, process, systemd-unit, ZFS, SMART, and optional UPS metrics and write Influx line protocol directly to VictoriaMetrics over loopback.
- Provisioned Grafana with the native VictoriaMetrics datasource plugin and changed dashboard datasource references accordingly.
- Retained `vmalert` for rule evaluation and added `nas-alert-router`, a dedicated-user Alertmanager-compatible notification endpoint with bounded input, atomic state, deduplication, simple inhibition, readiness/status endpoints, and optional direct ntfy delivery.
- Removed the Prometheus server configuration, Prometheus exporters, Alertmanager, the Alertmanager-to-ntfy bridge, the fallback Alertmanager package, and the unused Authentik Prometheus listener/runtime directory.
- Updated dashboards, alert expressions, live validation, VM guest checks, service/feature registries, reverse proxy routes, secret handling, and operator documentation for the new topology.

### Tooling and CI

- Consolidated Ruff and Pyright configuration into `pyproject.toml`.
- Added an unprivileged unit-test CI job.
- Made Cockpit CI require `package-lock.json`, use `npm ci`, and retain one exact lock/distribution artifact for downstream jobs instead of silently resolving with `npm install`.
- Added regression suites for capability policy, structured logging, alert routing, Prometheus-family dependency removal, Telegraf hardening, and the scheduler backend fix.

## Local validation completed

- Python unit tests: 243 passed.
- JavaScript unit tests: 13 passed.
- Python syntax validation: 48 files passed.
- Cockpit JavaScript and JSX syntax checks passed.
- Shell syntax checks passed.
- Repository scans found no active Prometheus service, Prometheus exporter, Alertmanager package/service, Prometheus Grafana datasource, Authentik Prometheus listener, or `PROMETHEUS_MULTIPROC_DIR` configuration.

## Qualification still required

The supplied source did not contain `cockpit/package-lock.json` or a compiled `cockpit/dist` bundle. Registry access was unavailable in this environment, so those exact bytes could not be reconstructed or honestly retained. The CI path now rejects that condition.

This environment also lacks Nix. The following remain mandatory before installation or a complete-release label:

- `nix flake check --no-build --show-trace`;
- evaluation of normal, CI-ready, and QEMU configurations;
- CI-ready and QEMU closure builds;
- native NixOS VM tests;
- official-ISO install/reboot testing;
- update/rollback, locked-boot, firewall, ZFS, backup/restore, and out-of-band recovery drills.

## Remaining backlog

Alpha.24 starts the valid backlog rather than claiming all recommendations are complete. The next source work should deepen secret rotation, complete the custom-root-service audit and privilege splitting, expand the shared readiness/state-authority registries, add business metrics and SLO/burn-rate rules, generate more policy/option documentation, add runbooks and service-specific dashboards, and incrementally improve failure-injection and VM subtest reporting.
