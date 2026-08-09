# Managed Services V2 application lifecycle policy

This document is part of the Unified Managed Services V2 implementation plan.
It defines **process lifetime** separately from **data lifetime** so low-idle-RAM
operation never risks deleting application state.

## Authority boundary

Managed Services V2 owns the desired lifecycle class for each application.
The native runtime (systemd/Podman/Compose/libvirt) still owns the actual process
or VM. V2 translates lifecycle intent into native start/stop operations.

Storage lifetime is independent and remains defined by `storageResources` and
`stateClass` (`authoritative`, `derived`, `cache`, `ephemeral`). Stopping or
reaping an application must never implicitly remove authoritative storage.

## Lifecycle modes

Every V2 application normalizes to one of four modes:

- `persistent`: start during V2 reconcile and keep running. If policy is
  reconciled after a crash/reboot, V2 asks the native runtime to restore it.
- `on-demand`: do not keep resident. The first authorized endpoint access wakes
  the app. Subsequent authorized requests refresh `lastAccess`. A timer/oneshot
  reaper stops it after `idleSeconds` with no resident lifecycle daemon.
- `manual`: never auto-start and never auto-reap. Explicit admin/user lifecycle
  commands control it.
- `disabled`: reconcile forces the runtime stopped and endpoint use fails closed.

`lifecycle.ephemeralRuntime=true` means the runtime instance/root filesystem may
be disposable. It does **not** mean storage is disposable. Pi is the main
example: its container is ephemeral, while per-user Pi home/session state is an
authoritative user-scoped storage resource.

Example:

```yaml
id: pi
lifecycle:
  mode: on-demand
  idleSeconds: 600
  ephemeralRuntime: true
storage:
  - resource: pi-home
    guestPath: /home/pi
    requiredCapabilities: [read, write]
```

A persistent service is equally explicit:

```yaml
id: vaultwarden
lifecycle:
  mode: persistent
  ephemeralRuntime: false
```

## Migration

The old `runtime.startPolicy` remains accepted only as migration input while the
repository is converted:

- `boot` -> `persistent`
- `on-demand` -> `on-demand`
- `manual` -> `manual`
- `disabled` -> `disabled`

If both old and new fields are present they must agree. Contradictory
`enabled`/`lifecycle` combinations fail validation rather than guessing.

## Runtime management

`nas-managed-service reconcile`:

- starts `persistent` applications;
- stops `disabled` applications;
- leaves `manual` applications unchanged;
- leaves `on-demand` applications asleep until use.

`nas-managed-service start|stop|restart <id>` performs an explicit native
runtime action. `start` refuses disabled applications.

`nas-managed-service touch <id>` records authorized activity for an on-demand
application. Managed endpoint authorization uses this automatically.

`nas-managed-service reap` stops on-demand applications whose last authorized
use exceeds `idleSeconds`.

A systemd timer runs `reap` as a oneshot. No `nas-appd`, polling daemon, or new
resident lifecycle controller is introduced.

## Endpoint behavior

For a managed endpoint:

1. Caddy invokes the existing NAS authorization gate.
2. Authentik-backed V2 capability authorization is evaluated.
3. If denied, no lifecycle action occurs.
4. If allowed and lifecycle is `on-demand`, V2 starts the native runtime on the
   first use or refreshes its activity timestamp on later use.
5. `manual` is never implicitly woken.
6. `disabled` fails closed.

Readiness/health verification should be performed after wake before forwarding
traffic as runtime-specific health metadata is migrated into V2.

## GUI

The admin V2 application editor should expose lifecycle as a first-class field:

- Always running (`persistent`)
- Start when used (`on-demand`) + idle timeout
- Manual
- Disabled

The UI must separately show storage persistence/backup classification so users
do not confuse "stop when idle" with "delete state".

## Acceptance tests

- persistent app is started by reconcile;
- disabled app is stopped by reconcile and cannot be auto-woken;
- manual app remains untouched by reconcile and endpoint access does not wake it;
- on-demand app wakes only after an authorized request;
- denied requests never start/touch an app;
- repeated authorized use extends the idle deadline without restarting the app;
- reaper stops only expired on-demand apps;
- stopping/reaping never deletes authoritative storage;
- reboot/reconcile restores persistent apps but leaves on-demand apps asleep;
- no resident process is added solely for lifecycle management.
