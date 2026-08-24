{ pkgs, ... }:

{
  # Compose is an ingestion format only.  The finite V2 reconcile invokes the
  # pinned Podlet binary when a canonical Compose import fingerprint changes;
  # generated workloads run solely through systemd + Podman Quadlet.
  systemd.services.nas-managed-services-reconcile.environment.NAS_V2_PODLET_BIN =
    "${pkgs.podlet}/bin/podlet";
}
