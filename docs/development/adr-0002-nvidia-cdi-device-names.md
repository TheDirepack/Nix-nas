# ADR-0002: Keep index and UUID NVIDIA CDI device names

## Status

Accepted

## Context

Managed Services V2 names NVIDIA GPUs for container runtimes with CDI
(`nvidia.com/gpu=<name>`). The NVIDIA container toolkit can generate those names
with three strategies; NixOS exposes `device-name-strategy` and appends
`extraArgs` to the generator command line.

The strategies do not name the same thing:

- index: the device's ordinal in NVML enumeration order;
- uuid: the driver's `GPU-<uuid>` identity, the same one `/proc/driver/nvidia/gpus/*/information`
  reports next to `Device Minor`.

`/dev/nvidiaN` is the **driver minor**, which is not the NVML enumeration index.
On a host with non-contiguous minors the index name therefore describes a GPU that
does not exist, while the UUID name always describes the right one.

Two requirements pull in opposite directions:

1. `services.yaml` may declare an accelerator explicitly as `nvidia.com/gpu=<index>`
   (accepted by the V3 schema and emitted verbatim into Compose overrides and
   Quadlet units). Those declarations keep working only while index names exist.
2. The inventory V2 advertises must identify the *physical* GPU, which only the
   UUID name does reliably.

Main already generates both names (`device-name-strategy = "index"` plus
`extraArgs = ["--device-name-strategy=uuid"]`); the probe still advertised index
names only.

## Decision

Keep both naming strategies at the toolkit layer and make the probe prefer UUID
names.

- `modules/nas/config/host-platform.nix` keeps index as the primary strategy and
  the UUID strategy in `extraArgs`, so the generator publishes one CDI device per
  GPU per strategy.
- `services/nas_v2_platform_probe.py` reads `Device Minor` and `GPU UUID` from
  `/proc/driver/nvidia/gpus/*/information` and emits `nvidia.com/gpu=GPU-<uuid>`
  when it can resolve one, falling back to `nvidia.com/gpu=<minor>` when it cannot
  or when the installed provider only publishes index names. The device-node
  selector is always emitted, so a GPU is never dropped from the inventory.
- The probe queries `nvidia-ctk cdi list` (via `--nvidia-ctk-bin`, with
  `NAS_V2_NVIDIA_CTK_BIN` and `PATH` as fallbacks) and only advertises names the
  provider reports. An empty result means the provider could not be consulted; the
  preferred name is then published anyway, which preserves the previous behaviour
  instead of silently removing every CDI selector.
- Duplicate driver minors and duplicate UUIDs fail closed with distinct errors.
- Because one GPU now appears under two names, the probe publishes `minorByUuid`
  with each NVIDIA accelerator entry and the resolver correlates a UUID CDI name
  with its `/dev/nvidiaN` before counting quantity. Without that map a 2-GPU host
  satisfies `quantity: 4` by handing out each GPU twice, so an inventory that
  advertises a UUID name without a mapping entry is refused instead of counted.
- `nas-managed-services-reconcile.service` `Wants=`/`After=` the
  `nvidia-container-toolkit-cdi-generator.service` and passes the toolkit store
  path, so the listing exists before the probe runs.

## Rejected alternative: UUID names only

Dropping the index strategy and advertising UUID names exclusively gives one
identity per GPU, but it makes every existing explicit
`nvidia.com/gpu=<index>` declaration in `services.yaml` unresolvable. The schema
still accepts it and the projections still emit it verbatim, so the failure
surfaces at container start rather than at validation: the runtime cannot find
the CDI device and the application does not start. On a host whose generator has
not been regenerated, UUID-only also loses the ability to advertise any CDI
device at all.

## Consequences

### Positive

- The advertised name identifies the physical GPU even when driver minors are
  non-contiguous.
- Explicit index declarations keep working, with no schema or services.yaml
  migration.
- Quantity counting counts each physical GPU once; requests above the physical
  count fail closed.

### Negative

- The inventory carries two names per GPU (plus the identity map), and the
  resolver must keep honoring it.
- The probe now depends on `/proc/driver/nvidia` and `nvidia-ctk` during
  reconciliation. A packaging or ordering mistake reduces the advertised
  selectors rather than failing the compile; the generator ordering and the
  preferred-name fallback bound that blast radius.
- Index-named fallbacks remain accepted, so the naming eras stay alive until
  explicit index declarations are retired.
