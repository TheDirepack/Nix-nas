# Managed Services V2 lifecycle policy

This document updates the Unified Managed Services V2 plan. It supersedes any older plan text that treats `boot`, `manual`, `disabled`, or an `ephemeralRuntime` boolean as the canonical application lifecycle model.

## Core rule

Application availability and runtime lifetime are separate V2 concepts:

- `enabled: false` means the application is unavailable and its managed runtime is stopped.
- `enabled: true` means the application is allowed to run; `lifecycle.mode` determines how long the runtime lives.

Storage lifetime is independent of runtime lifetime. Stopping or destroying a runtime must never imply deleting an authoritative V2 storage resource.

## Lifecycle modes

### `persistent`

Use for applications that should remain running while enabled.

Reconciliation starts or restores the native runtime. Examples include core infrastructure or frequently used applications whose startup cost or availability requirement justifies steady residency.

```yaml
id: jellyfin
enabled: true
lifecycle:
  mode: persistent
```

### `on-demand`

Use for applications that should consume no application RAM while idle.

The first authorized request starts the native runtime. Subsequent authorized requests refresh the last-use timestamp. A systemd timer runs a oneshot reaper and stops the runtime after `idleSeconds` with no resident scheduler daemon.

```yaml
id: grafana
enabled: true
lifecycle:
  mode: on-demand
  idleSeconds: 900
```

`idleSeconds` is required only for `on-demand` and is bounded to 30 seconds through 7 days.

### `session`

Use for explicitly launched disposable runtimes. A session launcher creates one runtime instance for a user/job and destroys it when that session ends. Generic static endpoint access must never auto-create a session runtime.

```yaml
id: pi
enabled: true
lifecycle:
  mode: session
```

Pi is the first target for this mode: its container root is disposable, while per-user home/session data and the selected workspace are separate V2 storage resources.

## Runtime behavior matrix

| enabled | lifecycle | reconcile | authorized static endpoint | idle reaper | explicit session launcher |
|---|---|---|---|---|---|
| false | any | stop | deny | ignore | deny |
| true | persistent | start/keep running | allow | ignore | not needed |
| true | on-demand | leave stopped/running state alone | start then touch | stop after idle timeout | not needed |
| true | session | stop stale generic runtime | deny static auto-start | ignore | create disposable instance |

## Migration from `runtime.startPolicy`

`runtime.startPolicy` remains accepted only as migration input:

- `boot` → `lifecycle.mode=persistent`
- `on-demand` → `lifecycle.mode=on-demand` with the migration default idle timeout
- `manual` → `lifecycle.mode=session`
- `disabled` requires `enabled=false`; when re-enabled the migrated lifecycle defaults to `persistent`

New V2 writes should use `enabled` plus `lifecycle` and should omit `runtime.startPolicy`.

## Runtime adapters

- Quadlet: persistent/on-demand use native Podman Quadlet; V2 storage is injected through native Quadlet drop-ins. Session workloads use `podman run --rm` or an equivalent native disposable Podman path.
- Compose: persistent/on-demand are supported when the application has a clear project lifecycle. Session mode is rejected unless an explicit disposable-session implementation exists.
- libvirt: persistent/on-demand may start/stop a declared native domain. Session mode is rejected until a disposable clone/overlay workflow is implemented safely.
- native/systemd services: persistent/on-demand should use systemd unit activation/stop semantics; prefer socket activation where upstream supports it.

## Low-memory requirement

There is no V2 lifecycle daemon. The design uses existing request handling plus systemd path/timer/oneshot activation:

1. reconcile oneshot enforces persistent/disabled state;
2. authorized access wakes/touches on-demand state;
3. a periodic systemd timer invokes a short-lived reaper;
4. session launchers own their child runtime lifetime directly.

The scheduler itself therefore has effectively zero steady-state userspace RSS.

## Next implementation sequence

1. finish migration of built-in/runtime-managed services to explicit lifecycle values;
2. convert Pi to a `session` Podman workload with persistent per-user V2 storage;
3. make Compose reject unsupported session lifecycle rather than guessing;
4. make libvirt reject unsupported session lifecycle and preserve all disks/data on removal;
5. expose lifecycle and idle timeout in the narrow Cockpit V2 application editor;
6. include lifecycle state in diagnostics/portal status without making visibility an authorization mechanism;
7. add VM tests proving persistent survives reconcile, on-demand wakes/reaps, disabled never wakes, and session runtime disappears while authoritative data remains.
