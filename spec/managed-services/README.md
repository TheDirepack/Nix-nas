# Managed Services V2 reference

The canonical, hand-edited Managed Services V2 specification is [`docs/development/managed-services-v2-spec.md`](../../docs/development/managed-services-v2-spec.md).

This directory contains the reference examples and the byte-identical schema mirror used by tests and tooling. Do not maintain a second copy of the specification here.

Managed Services **V2** is the project architecture name. Its current desired-state document uses `schemaVersion: 3`; those version numbers describe different layers and are intentionally not required to match.

The mutable desired-state authority remains `/var/lib/nas-control/services.yaml`.
